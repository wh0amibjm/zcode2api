"""验证码求解 + 预解 token 池。

通过 Node 子进程在 happy-dom 模拟浏览器环境中运行阿里云无痕 SDK，
求得 verifyParam（X-Aliyun-Captcha-Verify-Param）。

架构对齐 zapi captcha.ts 的预解池设计：
- 热路径永不等待：请求到来时直接从池里取一枚已解好的 token（亚毫秒），
  后台任务持续补充库存（目标 min，上限 max）。
- token 时效：verifyParam 实际 TTL ~2 分钟、且一次性（同一枚用过再带即 3007，
  见 experiments/probe_3007_isolation.py 实验 C），池内按 FIFO + 年龄淘汰。
- 挑战失效：上游回 3007 时只丢引发挑战的那一枚（on_challenge），池里其余
  token 不受牵连 —— 同一实验证明坏 token 被拒后新 token 照常可用；只有
  连续挑战之间没有任何成功，才认定系统性问题回退全清（旧 invalidate 语义）。
"""

from __future__ import annotations

import asyncio
import time

import httpx

from . import constants, logs, settings
from .store import store
from .upstream_http import SSL_CTX

# 池参数（对齐 zapi：min 20-40 / max 120 过重，单账号网关用小池足矣）
POOL_MIN = settings.CAPTCHA_POOL_MIN
POOL_MAX = settings.CAPTCHA_POOL_MAX
SOLVE_CONCURRENCY = settings.CAPTCHA_SOLVE_CONCURRENCY
TOKEN_TTL_MS = settings.CAPTCHA_TOKEN_TTL  # 单枚 token 的最大可用时长（ms）


class CaptchaSolveError(Exception):
    """验证码求解最终失败（重试耗尽/求解器不可用）。

    独立于 ClaimError 体系（验证码先于领域层使用），路由层按兜底回执处理。
    """


class _Token:
    __slots__ = ("param", "region", "born_at")

    def __init__(self, param: str, region: str | None) -> None:
        self.param = param
        self.region = region
        self.born_at = time.monotonic()

    def expired(self) -> bool:
        return (time.monotonic() - self.born_at) * 1000 >= TOKEN_TTL_MS


class CaptchaManager:
    def __init__(self) -> None:
        self._pool: asyncio.Queue[_Token] = asyncio.Queue(maxsize=POOL_MAX)
        self._pool_size = 0          # Queue 无可信 len，自行维护
        self._refill_task: asyncio.Task | None = None
        # 批次锁：同一时刻只允许一批补货在飞。热路径与后台循环都要走它 ——
        # 池空时 N 个并发请求曾经**各自**同步求解（各起一个 Node 进程），
        # 现在是排在同一个批次的锁上，批次内部按 _solve_sem 并发。
        self._refill_lock = asyncio.Lock()
        # 求解子进程的并发上限（跨批次共享，不能按批次新建，否则限流失效）
        self._solve_sem = asyncio.Semaphore(SOLVE_CONCURRENCY)
        self._config_lock = asyncio.Lock()
        self._config_cache: dict | None = None
        self._config_cache_at: float = 0.0
        self._last_error: str | None = None
        # 观测计数（管理端日志可读）：求解次数 / 成功数 / 累计求解秒数
        self._solve_calls = 0
        self._solve_ok = 0
        self._solve_seconds = 0.0
        # 热路径触发的补货任务强引用（事件循环只持弱引用，裸 create_task 会被 GC）
        self._bg_tasks: set[asyncio.Task] = set()
        # 连续挑战计数：两次挑战之间没有任何 note_accept() 就累加，达到升级阈值回退全清
        self._challenge_streak = 0

    def stats(self) -> dict:
        """池与求解的近况（诊断热路径为什么慢时先看这个）。"""
        avg = self._solve_seconds / self._solve_ok if self._solve_ok else 0.0
        return {
            "pool_size": self._pool_size,
            "pool_min": POOL_MIN,
            "pool_max": POOL_MAX,
            "concurrency": SOLVE_CONCURRENCY,
            "solve_calls": self._solve_calls,
            "solve_ok": self._solve_ok,
            "solve_success_rate": round(self._solve_ok / self._solve_calls, 3) if self._solve_calls else None,
            "solve_avg_seconds": round(avg, 2),
            "last_error": self._last_error,
        }

    # ── 配置 ─────────────────────────────────────────────────────────────────
    async def fetch_config(self) -> dict:
        now = time.time() * 1000
        if self._config_cache and now - self._config_cache_at < settings.CAPTCHA_CONFIG_CACHE_TTL:
            return self._config_cache
        async with self._config_lock:
            # 双检：等锁期间可能已被其他请求填充
            if self._config_cache and time.time() * 1000 - self._config_cache_at < settings.CAPTCHA_CONFIG_CACHE_TTL:
                return self._config_cache
            try:
                async with httpx.AsyncClient(timeout=15, verify=SSL_CTX) as client:
                    res = await client.get(
                        f"{constants.CLIENT_CONFIGS_URL}?{constants.CLIENT_CONFIGS_QUERY}"
                    )
                res.raise_for_status()
                captcha = ((res.json().get("data") or {}).get("configs") or {}).get("captcha")
                if captcha:
                    self._config_cache = captcha
                    self._config_cache_at = time.time() * 1000
                    return captcha
            except (httpx.HTTPError, ValueError) as err:
                logs.warn("captcha", f"获取配置失败，使用默认: {err}")
            return dict(constants.CAPTCHA_DEFAULTS)

    # ── 预解池 ───────────────────────────────────────────────────────────────
    def start(self) -> None:
        """启动后台补充循环（main.py lifespan 调用）。"""
        if self._refill_task is None or self._refill_task.done():
            self._refill_task = asyncio.create_task(self._refill_loop())

    async def close(self) -> None:
        # 后台补充循环 + 热路径经 _kick_refill 起的补货任务，一起收 —— 只取消前者的话，
        # 进程关停时正在求解的 Node 子进程会变成孤儿：Windows 上没人回收，还继续打上游。
        tasks = [t for t in self._bg_tasks if not t.done()]
        self._bg_tasks.clear()
        if self._refill_task and not self._refill_task.done():
            tasks.append(self._refill_task)
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001
                pass
        self._refill_task = None

    def _gate_open(self) -> bool:
        """是否允许预热：存在可走 Plan 对话的 jwt 账号才预热。

        apiKey 回退 / 废 JWT / 风控禁用 / 额度用完 / 冷却 都不需要验证码。
        账号冷却状态随 store 落库，重启后全冷却期间此门保持关闭。
        """
        return any(
            a.allows_billing() and a.is_selectable()
            for a in store.list_accounts("zai")
        )

    async def _refill_loop(self) -> None:
        while True:
            try:
                # 无可服务账号（全冷却/禁用/无号）：只淘汰过期 token，不解新码（不产生上游流量）
                if not self._gate_open():
                    await self._evict_expired()
                    await asyncio.sleep(3)
                    continue
                await self._refill_once()
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - 后台循环永不退出
                self._last_error = str(err)
                logs.warn("captcha", f"补充循环异常: {err}")
                await asyncio.sleep(5)

    async def _refill_once(self, floor: int = 0) -> int:
        """补一批：算 need → 并发求解 → 入池；返回补到的枚数。

        批次锁保证同一时刻只有一批在飞 —— 后台循环与热路径走同一条路，所以池空时
        N 个并发请求只会起 SOLVE_CONCURRENCY 个子进程，而不是 N 个（此前热路径各自
        同步求解，每个请求一个 Node 进程，池越空越雪崩）。

        `floor` 是"够用线"：池里已有 >= floor 枚就直接返回。热路径传 1 —— 排在锁上的
        第 2..N 个等待者醒来时货已被同批补上，不该再补一轮（否则每个等待者白等 2.4s）。
        """
        async with self._refill_lock:
            await self._evict_expired()          # 先淘汰，need 才是真实缺口
            if floor > 0 and self._pool_size >= floor:
                return 0
            need = POOL_MIN - self._pool_size
            if need <= 0:
                return 0
            config = await self.fetch_config()
            n = min(need, POOL_MAX - self._pool_size)
            if n <= 0:
                return 0
            results = await asyncio.gather(
                *(self._solve_guarded(config) for _ in range(n)),
                return_exceptions=True,
            )
            got = 0
            for res in results:
                if isinstance(res, _Token):
                    self._put(res)
                    got += 1
            return got

    async def _solve_guarded(self, config: dict) -> _Token | None:
        """受并发上限约束的求解。信号量是实例级的（跨批次共享）——
        按批次新建就等于没限流。"""
        async with self._solve_sem:
            return await self._solve_one(config)

    def _put(self, token: _Token) -> None:
        try:
            self._pool.put_nowait(token)
            self._pool_size += 1
        except asyncio.QueueFull:
            pass

    async def _evict_expired(self) -> None:
        kept: list[_Token] = []
        while True:
            try:
                token = self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            if not token.expired() and len(kept) < POOL_MAX:
                kept.append(token)
        for token in kept:
            self._put(token)

    def _take(self) -> _Token | None:
        """从池里取一枚未过期的 token（过期的顺手丢弃）。"""
        while self._pool_size > 0:
            try:
                token = self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            if not token.expired():
                return token
        return None

    def _kick_refill(self) -> None:
        """确保有一批补货在飞（幂等）。批次锁已经保证不会真的跑两批，
        这里只避免为每个请求都建一个必然空转的 task。"""
        if self._refill_lock.locked():
            return
        task = asyncio.create_task(self._refill_once())
        self._bg_tasks.add(task)             # 事件循环只持弱引用，裸 task 会被 GC
        task.add_done_callback(self._bg_tasks.discard)

    async def acquire_token(self, port: int | None = None) -> _Token:
        """取一枚可用 token：优先池内现成的（跳过过期），池空才等一轮共享补货。

        返回 token 对象而非裸 param：调用方被上游挑战时要能精确指认"是哪一枚
        被拒"，on_challenge 才能只丢它。region 可能为 None（旧求解器无 region 概念）。
        """
        # 1) 池内直取（热路径，亚毫秒）
        token = self._take()
        if token is not None:
            self._kick_refill()              # 取走一枚就补回一枚
            return token

        # 2) 池空：等一轮共享补货。并发请求在这里排队等**同一批**求解，
        #    而不是各自起一个 Node 进程 —— 这是并发不雪崩的关键。
        await self._refill_once(floor=1)
        token = self._take()
        if token is not None:
            self._kick_refill()
            return token

        # 3) 补货也没补到（求解器故障 / 上游风控）：池与求解的近况一起进日志 ——
        #    这是诊断"池为什么空/为什么慢"唯一的现场，别只留一句"失败"。
        logs.warn("captcha", f"池空且补货未果 {self.stats()}")
        raise CaptchaSolveError(f"验证码求解失败: {self._last_error or '多次重试无结果'}")

    async def get_verify_param(self, port: int | None = None) -> tuple[str, str | None]:
        """acquire_token 的旧签名封装（claim 等只需裸 param 的调用方）。"""
        token = await self.acquire_token(port)
        return token.param, token.region

    # ── 挑战处置（2026-09-27 重写，实验依据 experiments/probe_3007_isolation.py）──
    # 实验 A/B：垃圾 param 被 3007 后，紧接着用现解的新 token 请求 200 通过 ——
    # 挑战只打提出它的那一枚 token，不牵连池里其他 token。原先"任何一次 3007
    # 清空整池"因此是纯浪费：一池好 token 全扔，所有并发请求堵在补货批次锁上
    # 串行放行（线上 p99 首 token 52.7s 的主要来源）。
    # 保留的保守面：连续 _CHALLENGE_ESCALATION 次挑战之间没有任何成功，说明问题
    # 是系统性的（scene 配置错 / 指纹被整批拉黑），此时回退旧行为全清整池。
    _CHALLENGE_ESCALATION = 2

    def on_challenge(self, token: _Token | None = None) -> None:
        """上游对某枚 token 回 3007 后的池处置：默认只丢它。"""
        self._challenge_streak += 1
        if self._challenge_streak >= self._CHALLENGE_ESCALATION:
            self.invalidate()
            self._challenge_streak = 0
            return
        if token is not None:
            self._evict_token(token)

    def note_accept(self) -> None:
        """一枚 token 被上游正常消费（未挑战）后调用，重置连续挑战计数。"""
        self._challenge_streak = 0

    def _evict_token(self, token: _Token) -> None:
        """只把指定那一枚从池里去掉（按对象身份），其余 token 原序保留。"""
        kept: list[_Token] = []
        while True:
            try:
                candidate = self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            if candidate is not token and not candidate.expired():
                kept.append(candidate)
        for candidate in kept:
            self._put(candidate)

    # ── 求解 ─────────────────────────────────────────────────────────────────
    async def _solve_one(self, config: dict) -> _Token | None:
        scene = config.get("sceneId") or constants.CAPTCHA_DEFAULTS["sceneId"]
        region = config.get("region") or constants.CAPTCHA_DEFAULTS["region"]
        prefix = config.get("prefix") or constants.CAPTCHA_DEFAULTS["prefix"]

        self._solve_calls += 1
        t0 = time.monotonic()
        last_err: str | None = None
        for attempt in range(1, settings.CAPTCHA_SOLVE_RETRIES + 1):
            try:
                param = await self._run_solver(scene, region, prefix)
            except Exception as err:  # noqa: BLE001
                last_err = str(err)
                param = None
            if param:
                elapsed = time.monotonic() - t0
                self._solve_ok += 1
                self._solve_seconds += elapsed
                if attempt > 1:
                    logs.ok("captcha", f"求解成功（第 {attempt} 次尝试，{elapsed:.1f}s）")
                return _Token(param, region)
            self._last_error = last_err
            logs.warn("captcha", f"第 {attempt}/{settings.CAPTCHA_SOLVE_RETRIES} 次求解未果，重试…")

        logs.warn(
            "captcha",
            f"求解失败（耗时 {time.monotonic() - t0:.1f}s）: {last_err or '多次重试无结果'}",
        )
        return None

    async def _run_solver(self, scene: str, region: str, prefix: str) -> str | None:
        solver = settings.CAPTCHA_SOLVER_JS
        if not solver.exists():
            raise RuntimeError(
                f"未找到求解器 {solver}，请先在 captcha_node 下执行 npm install"
            )
        proc = await asyncio.create_subprocess_exec(
            settings.NODE_PATH, str(solver), scene, region, prefix,
            cwd=str(settings.CAPTCHA_SOLVER_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=settings.CAPTCHA_SOLVE_TIMEOUT)
        except asyncio.CancelledError:
            # 关停时被取消：子进程必须先杀掉再抛出，否则它继续跑完并打上游
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return None
        except FileNotFoundError as err:
            raise RuntimeError(f"无法启动 Node（{settings.NODE_PATH}）: {err}") from err

        param = None
        for line in stdout.decode("utf-8", "ignore").splitlines():
            if line.startswith("VERIFY_PARAM="):
                param = line[len("VERIFY_PARAM="):].strip()
        return param

    # ── 失效 ─────────────────────────────────────────────────────────────────
    def invalidate(self) -> None:
        """上游返回验证码挑战时清空整池（该批 token/指纹已不可信）。"""
        drained = 0
        while True:
            try:
                self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            drained += 1
        if drained:
            logs.warn("captcha", f"验证码失效，清空池 {drained} 枚")


captcha_manager = CaptchaManager()
