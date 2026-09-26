"""宿主机真实指纹采集 —— 诊断/测试用，不是账号入池默认源。

账号身份走 fingerprint.random_profile 的成套桌面 SKU（一号一台生成设备）。
本模块只描述部署机事实（Linux 云内核、无显示器 1920x1080 等），供
host_profile / 运维对照，禁止再当作多账号共用的上游身份。

采集项 ↔ DeviceProfile 字段：
  platform    platform.system()   → darwin / win32 / linux（官方 process.platform 语义）
  arch        platform.machine()  → arm64 / x64（官方 process.arch 语义）
  os_version  os.release() 语义   → 官方 X-Os-Version 直接用它
              （darwin/linux 取 platform.release()；**Windows 取 platform.version()**，
               因为 Python 的 release() 在 Windows 上是营销版本号 "10"/"11"，
               与 Node os.release() 的 NT 版本 "10.0.22631" 不同源 —— 见 _resolve_os_version）
  timezone    IANA 名。顺序：$TZ → Windows 注册表 TimeZoneKeyName（映射见
              _WIN_TZ_TO_IANA）→ /etc/localtime 符号链接反解 → 与
              /usr/share/zoneinfo 字节比对 → 失败退 UTC
  language    $LANG（zh_CN.UTF-8 → zh-CN；缺失退 en-US）
  screen      本机无显示器（服务器形态）→ 官方桌面端必有屏幕，取 HOST_FALLBACK
  device_mid  本模块不生成 —— DeviceProfile 缺省工厂给每次采集全新 UUID；
              MID 归属（全局持久化 / 每账号新装）由调用方决定
              （见 fingerprint.host_profile 的两种传参语义）

所有值仍过 fingerprint._validate 合规门：真机数据天然合规（Linux 内核版本
不在预置池时，_validate 按「版本形态」放行本机采集值，见 fingerprint 备注）。
"""

from __future__ import annotations

import os
import platform
import re
from pathlib import Path

# 服务器无显示器时的兜底分辨率（官方桌面端激活事件必有 screen_resolution）
FALLBACK_SCREEN = "1920x1080"

# Windows 注册表时区名 → IANA（官方 X-Client-Timezone 要 IANA 名）。
# Windows 的 [System.TimeZoneInfo]::Local.Id 给的是 "China Standard Time" 这种
# Windows 专名，标准库没有转换 API（.NET 6+ 的 TryConvertWindowsIdToIanaId 在
# PowerShell 5.1 / .NET Framework 上不存在），故内置常见项映射。
# **只列确定无疑的项；未命中一律退 UTC —— 猜错的时区比不知道更糟。**
_WIN_TZ_TO_IANA = {
    "UTC": "UTC",
    "China Standard Time": "Asia/Shanghai",
    "Taipei Standard Time": "Asia/Taipei",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "Singapore Standard Time": "Asia/Singapore",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Myanmar Standard Time": "Asia/Yangon",
    "India Standard Time": "Asia/Kolkata",
    "West Asia Standard Time": "Asia/Tashkent",
    "Arabian Standard Time": "Asia/Dubai",
    "Israel Standard Time": "Asia/Jerusalem",
    "Russian Standard Time": "Europe/Moscow",
    "Turkey Standard Time": "Europe/Istanbul",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Romance Standard Time": "Europe/Paris",
    "FLE Standard Time": "Europe/Kyiv",
    "E. Europe Standard Time": "Europe/Chisinau",
    "South Africa Standard Time": "Africa/Johannesburg",
    "Egypt Standard Time": "Africa/Cairo",
    "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver",
    "Pacific Standard Time": "America/Los_Angeles",
    "Alaskan Standard Time": "America/Anchorage",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "Atlantic Standard Time": "America/Halifax",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Argentina Standard Time": "America/Argentina/Buenos_Aires",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "W. Australia Standard Time": "Australia/Perth",
    "New Zealand Standard Time": "Pacific/Auckland",
}

# $LANG 形态解析：语言主码（2-3 位小写）+ 可选地区码
_LANG_RE = re.compile(r"^([a-z]{2,3})(?:[_-]([A-Za-z]{2,4}))?")


def win_tz_to_iana(name: str) -> str | None:
    """Windows 时区名 → IANA；未收录返回 None（调用方退 UTC，不猜）。"""
    return _WIN_TZ_TO_IANA.get((name or "").strip())


def _windows_timezone() -> str | None:
    """Windows 本机时区（注册表 TimeZoneKeyName → IANA）。

    Windows 没有 /etc/localtime，所以下面那条 Unix 通路在 Windows 上必然走到
    「退 UTC」—— 宿主时区永远显示 UTC 是**采集缺陷**而不是事实。这里补上注册表
    读取（`winreg` 仅在 Windows 存在，故延迟导入并容错）。
    """
    if platform.system().lower() != "windows":
        return None
    try:
        import winreg  # noqa: PLC0415 - Windows-only，必须延迟导入
    except ImportError:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        ) as key:
            name, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
    except OSError:
        return None
    return win_tz_to_iana(str(name))


def _resolve_timezone() -> str:
    """IANA 时区名：官方客户端读系统时区（Intl.resolvedOptions().timeZone）。

    解析顺序：
      0. $TZ —— 显式指定，跨平台都认（容器/CI 常用 `TZ=Asia/Shanghai`）
      1. Windows：注册表 TimeZoneKeyName → 内置映射（无 /etc/localtime）
      2. /etc/localtime 符号链接路径反解（darwin 通常如此）
      3. /etc/localtime 为实体文件时（部分 Linux 发行版是拷贝而非链接，
         如 pxed），与 /usr/share/zoneinfo 逐文件字节比对取唯一匹配
      4. 都失败退 UTC
    """
    tz_env = (os.environ.get("TZ") or "").strip()
    if "/" in tz_env and not tz_env.startswith("/"):
        return tz_env
    win = _windows_timezone()
    if win:
        return win
    path = Path("/etc/localtime")
    try:
        target = os.path.realpath(path)
        parts = Path(target).parts
        for i, seg in enumerate(parts):
            if seg == "zoneinfo" and i + 2 < len(parts):
                return f"{parts[i + 1]}/{parts[i + 2]}"
    except OSError:
        pass
    try:
        content = path.read_bytes()
    except OSError:
        return "UTC"
    zoneinfo_dir = Path("/usr/share/zoneinfo")
    if not zoneinfo_dir.is_dir():
        return "UTC"
    candidates: list[str] = []
    for f in zoneinfo_dir.rglob("*"):
        if not f.is_file() or f.suffix or f.is_symlink():
            continue  # 二进制 TZif 无后缀；跳过链接（posix/RIGHT 别名）与非数据文件
        rel = f.relative_to(zoneinfo_dir).as_posix()
        if rel.startswith(("Etc/", "posix/", "right/")) or rel in ("posixrules", "leapseconds"):
            continue
        if not rel[0].isupper():
            continue  # 真实地名以大写开头；纯缩写文件（CST 等）不作候选
        try:
            if f.read_bytes() == content:
                candidates.append(rel)
        except OSError:
            continue
    if not candidates:
        return "UTC"
    # Area/City 两段式优先于单段，字典序稳定输出
    candidates.sort(key=lambda r: (0 if "/" in r else 1, r))
    return candidates[0]


def _resolve_language() -> str:
    """语言标签：$LANG 的 zh_CN.UTF-8 形态转 zh-CN；无 Locale 环境退 en-US。

    官方桌面端 locale 来自系统偏好；Linux 容器常为 C/C.UTF-8（无语言信息），
    此时与官方常见默认 en-US 对齐（真实安装于裸 Locale 主机时同样如此）。
    """
    raw = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").strip()
    m = _LANG_RE.match(raw)
    if not m:
        return "en-US"
    lang, region = m.group(1), m.group(2)
    if not region:
        return {"zh": "zh-CN", "en": "en-US", "ja": "ja-JP", "ko": "ko-KR",
                "de": "de-DE", "fr": "fr-FR"}.get(lang, "en-US")
    return f"{lang}-{region.upper()}"


def _resolve_os_version() -> str:
    """X-Os-Version：对齐官方客户端的 `os.release()`（Node 语义）。

    三个平台里只有 Windows 的 Python 取值与 Node **不同源**：

      * darwin / linux —— `platform.release()` 就是内核版本（`23.6.0` /
        `6.8.0-45-generic`），与 `os.release()` 一致；
      * **Windows —— Python 的 `platform.release()` 返回营销版本号（`"10"` / `"11"`），
        而 Node 的 `os.release()` 返回 NT 版本（`"10.0.22631"`）。** 直接采前者会得到
        单段字符串，`fingerprint._validate(host_real=True)` 的形态门（要求 `数字.数字`）
        随即拒绝 —— 症状就是「Windows 宿主机上 `host_profile()` 直接抛
        ValueError: os_version 与平台不符: win32/11」。

    故 Windows 改用 `platform.version()`（NT 版本，与 Node 同源）；其余平台维持
    `platform.release()`（本就同源，不要动）。
    """
    if platform.system().lower() == "windows":
        nt = (platform.version() or "").strip()
        if re.match(r"^\d+\.\d+", nt):
            return nt
    return (platform.release() or "").strip() or "0.0"


def _normalize_arch(machine: str) -> str:
    # process.arch 语义：arm64 / x64（官方取值）；其余按 64 位推断为 x64
    m = (machine or "").lower()
    if "arm" in m or "aarch" in m:
        return "arm64"
    return "x64"


def _normalize_platform(system: str) -> str:
    return {"darwin": "darwin", "windows": "win32", "linux": "linux"}.get(
        (system or "").lower(), "linux")


def host_profile_cls():
    """延迟导入 DeviceProfile（避免与 fingerprint 循环依赖）。"""
    from .fingerprint import DeviceProfile
    return DeviceProfile


def collect_host_profile():
    """采集本机真实设备档案（每次调用重采，落库由调用方负责）。"""
    DeviceProfile = host_profile_cls()
    return DeviceProfile(
        platform=_normalize_platform(platform.system()),
        arch=_normalize_arch(platform.machine()),
        os_version=_resolve_os_version(),
        language=_resolve_language(),
        timezone=_resolve_timezone(),
        screen=FALLBACK_SCREEN,
    )
