"""套餐领取（Z.AI billing/preview + billing/claim）。

链路与 zcode-switch claim.rs 同形：
  1. GET  {BILLING_BASE}/billing/preview?app_version=&platform= → data.plans[]
  2. 领取需阿里云无痕验证码：CaptchaManager 服务端求解 → X-Aliyun-Captcha-Verify-Param
  3. POST {BILLING_BASE}/billing/claim  body {"plan_id":...}（+ 可选 Verify-Region 头）

上游业务码语义（沿用 zcode-switch 映射）：1001 套餐不存在 / 1002 活动结束 /
1003 已领取过 / 1004 不符合条件 / 1005 今日名额用完 / 3001 参数错误 /
3007 验证码失败（换验证码重试一次）/ 401 未登录。
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx

from . import constants, logs, settings
from .captcha import captcha_manager
from .models import Account, Status
from .upstream_http import SSL_CTX


class ClaimError(Exception):
    """业务失败（含上游 code 语义），message 面向用户。"""


AUTH_EXPIRED_MESSAGE = "凭证失效，请重新授权"

_CLAIM_FAIL = {
    1001: "套餐不存在",
    1002: "活动已结束或套餐暂不可领取",
    1003: "该套餐已经领取过",
    1004: "不符合领取条件",
    1005: "今日领取名额已用完",
    3001: "领取参数错误，请刷新后重试",
    3007: "验证码校验失败，请重试",
    401: "请先登录后再领取",
}


def billing_block_reason(account: Account, *, action: str = "领取") -> str | None:
    """JWT 不可打 billing 时的用户文案；可打则返回 None。"""
    if account.is_cooling():
        return f"账号冷却中（风控/限流），已跳过{action}"
    if account.mode != "jwt" or not (account.jwt_token or "").strip():
        return f"非 Coding Plan 账号，已跳过{action}"
    if not account.enabled:
        return f"账号已停用，已跳过{action}"
    if account.status == Status.DISABLED:
        return f"账号风控封禁，已跳过{action}"
    if account.status == Status.INVALID or not account.uses_plan_channel():
        return AUTH_EXPIRED_MESSAGE
    return None


def _mark_auth_failure(account: Account) -> None:
    from .store import store

    live = store.find(account.provider, account.id)
    if live is None:
        return
    live.status = Status.INVALID
    live.last_error = AUTH_EXPIRED_MESSAGE
    store.update_account(live)
    account.status = live.status
    account.last_error = live.last_error


def _fail_message(code: int, body: dict) -> str:
    base = _CLAIM_FAIL.get(code, "领取失败")
    server = body.get("msg") or body.get("message") or ""
    return f"{base}（{server}）" if server else base


def _business_code(body: dict) -> int:
    code = body.get("code")
    try:
        return int(code) if code is not None else -1
    except (TypeError, ValueError):
        return -1


def parse_plan(raw: dict) -> dict | None:
    """提取可领取套餐（plan_id/name/描述/优先级 + model_usage token 授权项）。"""
    plan_id = str(raw.get("plan_id") or raw.get("planId") or "").strip()
    if not plan_id:
        return None
    grants = []
    for ent in raw.get("entitlements") or []:
        if ent.get("meter") != "model_usage" or ent.get("unit_type") != "token":
            continue
        name = str(ent.get("show_name") or ent.get("showName") or "").strip()
        if not name:
            continue
        units = ent.get("grant_units", ent.get("grantUnits")) or 0
        grants.append({
            "name": name,
            "units": float(units),
            "period": ent.get("period") or "one_time",
        })
    return {
        "plan_id": plan_id,
        "name": str(raw.get("name") or "").strip(),
        "description": str(raw.get("description") or "").strip(),
        "priority": raw.get("priority") or 0,
        "grants": grants,
    }


async def _billing_request(account: Account, method: str, path: str, **kwargs) -> dict:
    headers = dict(kwargs.pop("headers"))
    try:
        async with httpx.AsyncClient(timeout=25, verify=SSL_CTX) as client:
            res = await client.request(
                method, f"{settings.ZCODE_BILLING_BASE}{path}",
                headers=headers, **kwargs,
            )
    except httpx.HTTPError as err:
        # 连接/超时等网络故障统一转业务错误：路由层只需面对 ClaimError 一种失败
        raise ClaimError(f"上游网络错误: {err}") from err
    if res.status_code in (401, 403):
        text = (res.text or "").lower()
        if "captcha" not in text and "verify" not in text:
            _mark_auth_failure(account)
            raise ClaimError(AUTH_EXPIRED_MESSAGE)
    try:
        body = res.json()
    except ValueError:
        raise ClaimError(f"上游响应非 JSON HTTP {res.status_code}") from None
    return body


def jwt_user_id(account: Account) -> str | None:
    """JWT payload 的 user_id（zcode-switch telemetry_user_id 同源语义）。

    官方客户端事件上报以 user_id 标识用户；hub 不存 user_info，直接从 JWT
    解出（user_id 优先，sub 兜底，两者同为 36 位 uuid）。
    """
    token = (account.jwt_token or "").strip()
    if not token:
        return None
    try:
        seg = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (IndexError, ValueError):
        return None
    uid = payload.get("user_id") or payload.get("sub")
    if not isinstance(uid, str) or not uid.strip():
        return None
    return uid.strip()


async def report_activation_events(account: Account) -> str | None:
    """上报官方客户端激活事件（app_launch + app_daily_active），返回错误或 None。

    zcode-switch claim_refresh 同形：preview 前模拟桌面端当日活跃（疑似活动
    套餐投放资格信号）。事件体/端点/业务码判定收敛在 telemetry 单一事实源；
    请求无 Authorization（上游事件端点不校验）；任何失败仅返回文案，不阻断
    preview，首个失败即中止（日活键在上游按 device_mid+日期去重，重试无意义）。
    """
    from .fingerprint import profile_for
    from .telemetry import post_activation_event

    profile = profile_for(account)
    user_id = jwt_user_id(account)
    if not user_id:
        return "JWT 无 user_id，跳过激活上报"
    for element in constants.ACTIVATION_ELEMENTS:
        try:
            await post_activation_event(profile, user_id, element)
        except (httpx.HTTPError, RuntimeError) as err:
            return f"激活事件 {element} 上报失败: {err}"
    return None


async def auto_claim_all_plans(account: Account, initial_delay: float | None = None) -> list[dict]:
    """新账号入池自动领取：激活上报 + 逐个领取全部可领套餐。

    入池链路的 fire-and-forget 收尾：任何失败只记日志/返回 outcome，绝不抛出
    （入池流程不受影响）。重复执行安全（上游 1003 已领取过幂等）。

    `initial_delay`：入池那一次传 `settings.CLAIM_SETTLE_SECONDS` —— OAuth 刚拿到 JWT 时站点侧
    （billing）可能还没同步完这个账号，**此刻打过去必然领不到**（2026-09-26 观察：同一批号里
    有的领到、有的报失败，差别就在这几秒）。先等它落定，比撞了再重试更省事。周期轮询
    （ClaimMonitor）不传 —— 那些账号早就稳定了。
    """
    if not (account.mode == "jwt" and account.jwt_token):
        return []
    if initial_delay and initial_delay > 0:
        await asyncio.sleep(initial_delay)
    outcomes: list[dict] = []

    try:
        err = await report_activation_events(account)
        if err:
            logs.warn("claim", f"账号 {account.name} 激活上报失败: {err}")
    except Exception as err:  # noqa: BLE001 - 激活失败不阻断领取
        logs.warn("claim", f"账号 {account.name} 激活上报异常: {err}")

    try:
        plans = await preview_plans(account)
    except ClaimError as err:
        logs.info("claim", f"账号 {account.name} 无可领套餐（{err}）")
        return outcomes
    except Exception as err:  # noqa: BLE001
        logs.warn("claim", f"账号 {account.name} preview 异常: {err}")
        return outcomes

    if not plans:
        logs.info("claim", f"账号 {account.name} 上游无投放套餐，跳过领取")
        return outcomes

    for plan in plans:
        for attempt in (1, 2):
            try:
                result = await claim(account, plan["plan_id"])
                outcomes.append({"account_id": account.id, "account_name": account.name,
                                 "ok": True, **result})
                logs.ok("claim", f"账号 {account.name} 自动领取成功: "
                                 f"{result.get('plan_name') or plan['plan_id']}")
                break
            except ClaimError as err:
                # 业务失败（已领取过 / 条件不符 / 名额用完）：上游的确定性回答，重试没有意义
                outcomes.append({"account_id": account.id, "account_name": account.name,
                                 "ok": False, "plan_id": plan["plan_id"], "message": str(err)})
                logs.warn("claim", f"账号 {account.name} 自动领取 {plan['plan_id']} 失败: {err}")
                break
            except Exception as err:  # noqa: BLE001
                # 瞬时失败：验证码预解池那侧的 pe 字节码 VM 会偶发 stall，solver 逐出缓存后
                # 下一次就好（2026-09-26 实测：自动领取报"验证码求解失败"后，手动重跑立刻成功）。
                # 这类失败重试一次就能吃回来，否则只能等下一个周期（6h）或人工点。
                if attempt == 1:
                    logs.warn("claim", f"账号 {account.name} 领取遇瞬时异常，"
                                       f"{settings.CLAIM_RETRY_WAIT}s 后重试一次: {err}")
                    await asyncio.sleep(settings.CLAIM_RETRY_WAIT)
                    continue
                outcomes.append({"account_id": account.id, "account_name": account.name,
                                 "ok": False, "plan_id": plan["plan_id"], "message": str(err)})
                logs.warn("claim", f"账号 {account.name} 自动领取异常: {err}")
    return outcomes


async def preview_plans(account: Account) -> list[dict]:
    """拉取账号当前可领取套餐，按优先级降序。"""
    blocked = billing_block_reason(account, action="上游查询")
    if blocked:
        raise ClaimError(blocked)
    from .fingerprint import profile_for
    from .quota import _auth_headers

    body = await _billing_request(
        account, "GET", "/billing/preview",
        headers=_auth_headers(account),
        # platform 跟账号档案走（官方 TH() = process.platform-arch）；
        # 实测 client/configs 才拒 platform 参数，preview 宽容。
        params={"app_version": constants.BILLING_APP_VERSION,
                "platform": profile_for(account).platform_full},
    )
    code = _business_code(body)
    if code != 0:
        raise ClaimError(_fail_message(code, body))
    raw_plans = (body.get("data") or {}).get("plans") or []
    plans = [parsed for parsed in (parse_plan(p) for p in raw_plans) if parsed]
    plans.sort(key=lambda p: (-p["priority"], p["plan_id"]))
    return plans


async def _auto_pick_plan(account: Account, plan_id: str | None) -> tuple[str, str, list]:
    """plan_id 为空时 preview 自动选优先级最高套餐。返回 (plan_id, plan_name, grants)。"""
    if plan_id:
        return plan_id, "", []
    plans = await preview_plans(account)
    if not plans:
        raise ClaimError("没有待领取的套餐")
    best = plans[0]
    return best["plan_id"], best["name"] or best["plan_id"], best["grants"]


def _claim_headers(account: Account, verify_param: str, region: str | None) -> dict:
    """billing/claim 客户端请求头形态（asar claimManualPlan）。

    实测缺版本/平台头时即使验证码有效也 3007；X-Device-Mid 由 _auth_headers 提供。
    """
    from .quota import _auth_headers

    headers = _auth_headers(account)
    headers[constants.CAPTCHA_HEADER] = verify_param
    if region and region.strip():
        headers["X-Aliyun-Captcha-Verify-Region"] = region.strip()
    # 实测缺版本/平台头时即使验证码有效也 3007（_auth_headers 已带，此处显式
    # 兜底防止基座头漂移）。平台必须跟账号档案走，禁止再盖成全局 darwin-arm64。
    headers["X-ZCode-App-Version"] = constants.BILLING_APP_VERSION
    return headers


async def _post_claim(account: Account, headers: dict, plan_id: str) -> dict:
    """提交 billing/claim 并翻译业务码。"""
    body = await _billing_request(
        account, "POST", "/billing/claim",
        headers=headers, json={"plan_id": plan_id},
    )
    code = _business_code(body)
    if code != 0:
        raise ClaimError(_fail_message(code, body))
    return body


async def claim_with_captcha(
    account: Account,
    verify_param: str,
    region: str | None,
    plan_id: str | None = None,
) -> dict:
    """手动领取：verify_param 由用户浏览器内阿里 SDK 滑块产生，本端只做转发。

    plan_id 缺省时先 preview 自动选优先级最高套餐（无需验证码）。
    """
    if not (account.mode == "jwt" and account.jwt_token):
        raise ClaimError("仅 Coding Plan (JWT) 账号支持领取")
    blocked = billing_block_reason(account)
    if blocked:
        raise ClaimError(blocked)
    if not (verify_param or "").strip():
        raise ClaimError("缺少验证码参数，请先完成人机验证")

    plan_id, plan_name, grants = await _auto_pick_plan(account, plan_id or None)
    headers = _claim_headers(account, verify_param.strip(), region)
    await _post_claim(account, headers, plan_id)
    return {"plan_id": plan_id, "plan_name": plan_name, "grants": grants}


async def claim(account: Account, plan_id: str | None = None) -> dict:
    """领取套餐。plan_id 缺省时自动选优先级最高的可领套餐。

    返回 {"plan_id", "plan_name", "grants"}；3007（验证码失败）自动换码重试一次。
    """
    if not (account.mode == "jwt" and account.jwt_token):
        raise ClaimError("仅 Coding Plan (JWT) 账号支持领取")
    blocked = billing_block_reason(account)
    if blocked:
        raise ClaimError(blocked)

    plan_id, plan_name, grants = await _auto_pick_plan(account, plan_id)
    last_err: ClaimError | None = None
    for attempt in (1, 2):
        token = await captcha_manager.acquire_token()
        config = await captcha_manager.fetch_config()
        headers = _claim_headers(account, token.param, token.region or config.get("region"))

        body = await _billing_request(
            account, "POST", "/billing/claim",
            headers=headers, json={"plan_id": plan_id},
        )
        code = _business_code(body)
        if code == 0:
            captcha_manager.note_accept()
            return {"plan_id": plan_id, "plan_name": plan_name, "grants": grants}
        if code == 3007:
            # 无条件上报挑战：token 信号要进池的 streak 统计，attempt==2 才终止
            captcha_manager.on_challenge(token)
            if attempt == 1:
                logs.warn("claim", f"账号 {account.name} 验证码被拒，换码重试")
                last_err = ClaimError(_fail_message(code, body))
                continue
            raise ClaimError(_fail_message(code, body))
        raise ClaimError(_fail_message(code, body))
    raise last_err or ClaimError("领取失败")


class ClaimMonitor:
    """后台周期性检查活动投放并自动领取。

    基座的自动领取只在**入池那一刻**跑（admin_api 的 add_accounts / oauth login /
    import 三处），而活动是**分批投放**的：2026-09-26 实测同一个账号的 preview 先只有
    `zcode-v3-start-plan-0926`（GLM-5.3-Flash 1 亿），十几分钟后才出现
    `zcode-v3-start-plan-0924-wk-2`（周末场 3 亿）。入池时那一次因此会漏掉后续场次，
    只能人工去后台点领取。

    节拍刻意拉长、账号之间还错峰（默认 1800s / 5s，`ZCODE_CLAIM_INTERVAL` 设 0 关闭）：
    `billing/*` 是上游 WAF 风险点，连续查询容易触发拦截
    （docs/development/05-upstream-protocols.md §7 风险控制）。重复领取本身是幂等的 ——
    上游回 1003「已领取过」，不会重复发放。
    """

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def run_once(self) -> list[str]:
        """跑一轮：对每个合格账号做一次「激活上报 + preview + 领取」。

        写成独立方法而不是塞进循环体，是为了可测 —— 循环只负责节拍。返回本轮实际
        尝试过的账号名，便于断言与排障。
        """
        from .store import store

        attempted: list[str] = []
        for acc in store.list_accounts("zai"):
            if self._stop.is_set():
                break
            if acc.mode != "jwt" or not acc.allows_billing():
                continue
            live = store.find(acc.provider, acc.id)
            if live is None or not live.allows_billing():
                continue
            try:
                await auto_claim_all_plans(live)
                attempted.append(live.name)
            except Exception as err:  # noqa: BLE001 - 单账号失败不拖垮整轮
                logs.warn("claim", f"账号 {live.name} 周期领取异常: {err}")
            await asyncio.sleep(settings.CLAIM_STAGGER)  # 错峰，别连打 billing
        return attempted

    async def _loop(self) -> None:
        # 先让位给启动安装序与额度首刷
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=settings.CLAIM_START_DELAY)
            return
        except TimeoutError:
            pass

        while not self._stop.is_set():
            interval = settings.CLAIM_INTERVAL
            if interval > 0:
                try:
                    await self.run_once()
                except Exception as err:  # noqa: BLE001 - 后台任务需吞掉异常继续运行
                    logs.err("claim", f"后台领取轮询出错: {err}")
            wait = interval if interval > 0 else 60
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=wait)
            except TimeoutError:
                continue

    def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            # 必须 cancel，光 set 事件停不下来：`run_once()` 里的 billing 网络请求、
            # 以及账号之间的错峰等待（CLAIM_STAGGER）都不检查 `_stop`，于是一次 6 小时
            # 周期的关停会被阻塞到整轮跑完（账号数 × stagger + 每账号请求耗时，分钟级）。
            # 领取本身幂等（上游回 1003 已领取过），中断安全。
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None


claim_monitor = ClaimMonitor()
