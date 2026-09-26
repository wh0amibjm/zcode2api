"""客户端版本号的上游探测 —— 让 `CLIENT_APP_VERSION` 不再写死。

**为什么必须自动更新**：版本号是 **start-plan 的额度闸门**，不是指纹微调。
2026-09-26 实测：报 `3.11.2` 时上游对账号连 plan 都不下发（`billing/current` 与
`billing/balance` 都是空数组、`billing/preview` 里没有可领活动、messages 一律
HTTP 200 + `{"code":1005,"msg":"exceed quota limit"}`）；换 `3.14.1` 后同一账号立刻
恢复。写死的代价就是**上游每升一次版本，这边静默失去额度**，而症状偏偏是"额度超限"
这种把人往错方向带的文案。

**来源**：官网首页 `https://zcode.z.ai/cn` 里带着全部版本的 CDN 下载链
（`cdn-zcode.z.ai/zcode/electron/releases/<ver>/<platform>/…`），取其中最大版本号，
再用一次 HEAD 确认该版本的包确实在 CDN 上 —— 首页是 SSG 产物，可能滞后或领先于实际
发布，所以「首页说最大」不等于「真的能下」。CDN 不给目录列表（`NoSuchKey`），
`latest.yml` 是按版本目录放的，两条路都拿不到"最新"。

**失败一律保持原值**：探测是改进，不是依赖。探测不到时用编译期兜底值继续跑，
额度该没有还是没有，但不会因为探测本身挂掉。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

from . import constants, logs, settings
from .upstream_http import SSL_CTX

HOME_ORIGIN = "https://zcode.z.ai"
HOME_PATHS = ("/cn", "/")          # 中文站优先；两站内容一致，互为兜底
CDN_BASE = "https://cdn-zcode.z.ai/zcode/electron/releases"
# 首页里版本以 CDN 路径形态出现：.../releases/3.14.3/windows-x64/...
_VERSION_RE = re.compile(r"/releases/(\d+\.\d+\.\d+)/")
# CDN 上确认包存在用哪个平台（任一存在即可，用 x64 最稳）
_PROBE_ARTIFACT = "windows-x64/ZCode-{v}-win-x64.exe"

CACHE_TTL = 6 * 3600               # 秒；版本变动以周计，6 小时足够新鲜


def cache_path() -> Path:
    """缓存文件位置。运行时求值 —— 测试会改 DATA_DIR 做隔离，import 期定死就搬不动。"""
    return Path(settings.DATA_DIR) / "upstream_version.json"


def newest_version(candidates) -> str | None:
    """语义化版本取最大（按数字段比，不是字典序 —— 否则 3.9.0 > 3.14.1）。"""
    parsed = []
    for v in candidates or ():
        parts = str(v).split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            parsed.append((tuple(int(p) for p in parts), str(v)))
    return max(parsed)[1] if parsed else None


def extract_versions(html: str) -> list[str]:
    """从首页 HTML 里抽出全部版本号（去重）。"""
    return sorted(set(_VERSION_RE.findall(html or "")))


def read_cache(now: float | None = None) -> str | None:
    """读未过期的缓存版本；过期/损坏/不存在都返回 None。"""
    try:
        raw = json.loads(cache_path().read_text(encoding="utf-8"))
        version = str(raw.get("version") or "")
        at = float(raw.get("at") or 0)
    except (OSError, ValueError, TypeError):
        return None
    now = now if now is not None else time.time()
    if not version or now - at > CACHE_TTL:
        return None
    return version


def write_cache(version: str, now: float | None = None) -> None:
    """写缓存；失败只记日志（缓存是优化，不是正确性依赖）。"""
    try:
        path = cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": version, "at": now if now is not None else time.time()}),
            encoding="utf-8",
        )
    except OSError as err:
        logs.warn("version", f"版本缓存写入失败: {err}")


async def detect(client: httpx.AsyncClient) -> tuple[str | None, str]:
    """探测官方当前版本，返回 (版本或 None, 依据文案)。只读，不写任何状态。"""
    versions: list[str] = []
    last_err = ""
    for path in HOME_PATHS:
        try:
            res = await client.get(HOME_ORIGIN + path)
            res.raise_for_status()
        except httpx.HTTPError as err:
            last_err = f"{path} 拉取失败: {err}"
            continue
        versions = extract_versions(res.text)
        if versions:
            break
    best = newest_version(versions)
    if not best:
        return None, last_err or "首页里没有版本链（页面结构可能已变）"

    # 首页是构建产物，可能滞后或领先；用一次 HEAD 确认包真在 CDN 上
    probe = f"{CDN_BASE}/{best}/{_PROBE_ARTIFACT.format(v=best)}"
    try:
        head = await client.head(probe)
    except httpx.HTTPError as err:
        return None, f"首页最大值 {best}，但 CDN 校验失败: {err}"
    if head.status_code >= 400:
        return None, f"首页最大值 {best}，但 CDN 上没有该版本包（HTTP {head.status_code}）"
    return best, f"首页最大值 {best}，CDN 已确认"


async def refresh(force: bool = False) -> str | None:
    """完整流程：缓存 → 探测 → 写回 constants。返回最终生效版本（None = 保持原值）。"""
    version = None
    if not force:
        version = read_cache()
        if version:
            if constants.set_client_app_version(version):
                logs.info("version", f"客户端版本取自缓存: {version}")
            return version

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=15.0, read=30.0, write=15.0, pool=15.0),
        follow_redirects=True,
        headers={"User-Agent": constants.USER_AGENT},
        verify=SSL_CTX,
    ) as client:
        version, why = await detect(client)

    if not version:
        logs.warn("version", f"版本探测未采用: {why}（保持 {constants.CLIENT_APP_VERSION}）")
        return None

    changed = constants.set_client_app_version(version)
    write_cache(version)
    if changed:
        logs.ok("version", f"客户端版本对齐上游: {why}")
    else:
        logs.info("version", f"客户端版本已是最新: {version}")
    return version
