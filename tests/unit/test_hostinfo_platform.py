"""宿主机采集的跨平台语义。

这三条是被真实故障逼出来的 —— 在 Windows 上跑 `fingerprint.host_profile()` 直接抛
`ValueError: os_version 与平台不符: win32/11`：Python 的 `platform.release()` 在
Windows 返回**营销版本号**（"10"/"11"），而官方客户端的 `os.release()`（Node）
返回 **NT 版本**（"10.0.22631"）。同理时区：Windows 没有 `/etc/localtime`，
原来必然退化成 UTC —— 那是采集缺陷，不是宿主机事实。

测试用 monkeypatch 模拟三种平台，所以在任何宿主机上都能跑。
"""

from __future__ import annotations


class TestOsVersionSource:
    def test_windows_uses_nt_version_not_marketing_name(self, monkeypatch):
        """Windows：取 platform.version()（NT 版本，与 Node os.release() 同源）。"""
        from app import hostinfo

        monkeypatch.setattr(hostinfo.platform, "system", lambda: "Windows")
        monkeypatch.setattr(hostinfo.platform, "release", lambda: "11")          # 营销名
        monkeypatch.setattr(hostinfo.platform, "version", lambda: "10.0.22631")  # NT 版本
        assert hostinfo._resolve_os_version() == "10.0.22631"

    def test_windows_falls_back_when_nt_version_is_odd(self, monkeypatch):
        """NT 版本取不到正常形态时，退回 release()，最终仍有 "0.0" 兜底。"""
        from app import hostinfo

        monkeypatch.setattr(hostinfo.platform, "system", lambda: "Windows")
        monkeypatch.setattr(hostinfo.platform, "release", lambda: "11")
        monkeypatch.setattr(hostinfo.platform, "version", lambda: "")
        assert hostinfo._resolve_os_version() == "11"

    def test_unix_keeps_kernel_release(self, monkeypatch):
        """darwin / linux 的 release() 本就是内核版本，别动它。"""
        from app import hostinfo

        monkeypatch.setattr(hostinfo.platform, "system", lambda: "Linux")
        monkeypatch.setattr(hostinfo.platform, "release", lambda: "6.8.0-45-generic")
        monkeypatch.setattr(hostinfo.platform, "version", lambda: "#45-Ubuntu SMP")
        assert hostinfo._resolve_os_version() == "6.8.0-45-generic"

    def test_windows_host_profile_passes_validation(self, monkeypatch):
        """回归：Windows 宿主机上 host_profile() 必须不抛（曾因 release()="11" 被形态门拒绝）。"""
        from app import hostinfo
        from app.fingerprint import host_profile

        monkeypatch.setattr(hostinfo.platform, "system", lambda: "Windows")
        monkeypatch.setattr(hostinfo.platform, "release", lambda: "11")
        monkeypatch.setattr(hostinfo.platform, "version", lambda: "10.0.22631")
        monkeypatch.setattr(hostinfo.platform, "machine", lambda: "AMD64")
        monkeypatch.delenv("TZ", raising=False)

        p = host_profile()                     # 不抛即通过
        assert p.platform == "win32"
        assert p.arch == "x64"
        assert p.os_version == "10.0.22631"


class TestTimezoneSource:
    def test_windows_zone_name_maps_to_iana(self):
        """注册表给的是 Windows 专名，官方头要 IANA 名。"""
        from app import hostinfo

        assert hostinfo.win_tz_to_iana("China Standard Time") == "Asia/Shanghai"
        assert hostinfo.win_tz_to_iana("Tokyo Standard Time") == "Asia/Tokyo"
        assert hostinfo.win_tz_to_iana("UTC") == "UTC"

    def test_unknown_windows_zone_is_not_guessed(self):
        """未收录的时区返回 None —— 猜错的时区比不知道更糟。"""
        from app import hostinfo

        assert hostinfo.win_tz_to_iana("Middle-earth Standard Time") is None
        assert hostinfo.win_tz_to_iana("") is None

    def test_tz_env_wins_and_is_not_mistaken_for_a_path(self, monkeypatch):
        """$TZ 显式指定优先（容器/CI 常用）；文件路径形态不得被当成时区名。"""
        from app import hostinfo

        monkeypatch.setenv("TZ", "Asia/Shanghai")
        assert hostinfo._resolve_timezone() == "Asia/Shanghai"

        monkeypatch.setenv("TZ", "/etc/localtime")   # 路径形态：不采信
        tz = hostinfo._resolve_timezone()
        assert not tz.startswith("/")
