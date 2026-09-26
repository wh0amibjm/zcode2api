"""客户端版本探测 —— 让版本号不写死。

版本号是 start-plan 的**额度闸门**：写死则上游每升一次版本，这边就静默失去额度，
而症状偏偏是 "exceed quota limit" 这种把人往错方向带的文案（2026-09-26 实测：
报 3.11.2 时 billing 空数组 + messages 回 200/code 1005；换 3.14.1 立刻恢复）。

这里钉住纯逻辑与**失败路径**——探测是改进不是依赖，探不到必须原样保持旧版本。
网络用 httpx.MockTransport 注入，不打真实上游。
"""

from __future__ import annotations

import time

import httpx

from app import constants, settings
from app import upstream_version as uv

HOME_HTML = (
    '<a href="https://cdn-zcode.z.ai/zcode/electron/releases/3.11.2/macos-arm64/ZCode-3.11.2-mac-arm64.dmg">'
    '<a href="https://cdn-zcode.z.ai/zcode/electron/releases/3.14.3/windows-x64/ZCode-3.14.3-win-x64.exe">'
    '<a href="https://cdn-zcode.z.ai/zcode/electron/releases/3.9.0/windows-x64/ZCode-3.9.0-win-x64.exe">'
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestNewestVersion:
    def test_compares_numerically_not_lexically(self):
        """字典序会把 3.9.0 判成比 3.14.3 新 —— 必须按数字段比。"""
        assert uv.newest_version(["3.9.0", "3.14.1", "3.14.3", "3.2.0"]) == "3.14.3"

    def test_ignores_non_versions(self):
        assert uv.newest_version(["junk", "1.2", ""]) is None
        assert uv.newest_version([]) is None
        assert uv.newest_version(None) is None


class TestExtractVersions:
    def test_pulls_versions_out_of_cdn_links(self):
        assert uv.extract_versions(HOME_HTML) == ["3.11.2", "3.14.3", "3.9.0"]

    def test_page_without_links_yields_nothing(self):
        assert uv.extract_versions("<html>nothing here</html>") == []


class TestCache:
    def test_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
        uv.write_cache("3.14.3")
        assert uv.read_cache() == "3.14.3"

    def test_expired_cache_is_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
        uv.write_cache("3.14.3", now=time.time() - uv.CACHE_TTL - 1)
        assert uv.read_cache() is None

    def test_corrupt_cache_is_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
        uv.cache_path().parent.mkdir(parents=True, exist_ok=True)
        uv.cache_path().write_text("{not json", encoding="utf-8")
        assert uv.read_cache() is None


class TestDetect:
    async def test_detects_newest_confirmed_by_cdn(self):
        def handler(request):
            return httpx.Response(200, text=HOME_HTML) if request.method == "GET" else httpx.Response(200)

        async with _client(handler) as client:
            version, why = await uv.detect(client)
        assert version == "3.14.3"
        assert "已确认" in why

    async def test_rejects_version_missing_on_cdn(self):
        """首页是 SSG 产物，可能领先于实际发布 —— CDN 上没有就不能采信。"""
        def handler(request):
            return httpx.Response(200, text=HOME_HTML) if request.method == "GET" else httpx.Response(404)

        async with _client(handler) as client:
            version, why = await uv.detect(client)
        assert version is None
        assert "CDN" in why

    async def test_network_failure_is_not_fatal(self):
        def handler(request):
            raise httpx.ConnectError("offline")

        async with _client(handler) as client:
            version, why = await uv.detect(client)
        assert version is None
        assert why


class TestRefreshKeepsOldValueOnFailure:
    async def test_probe_failure_keeps_current_version(self, tmp_path, monkeypatch):
        """探测失败绝不改版本 —— 它是改进，不是依赖。"""
        monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(constants, "_CLIENT_APP_VERSION", "9.9.9")

        def handler(request):
            raise httpx.ConnectError("offline")

        real = httpx.AsyncClient
        monkeypatch.setattr(uv.httpx, "AsyncClient",
                            lambda **kw: real(transport=httpx.MockTransport(handler)))

        assert await uv.refresh(force=True) is None
        assert constants.CLIENT_APP_VERSION == "9.9.9"
        assert constants.USER_AGENT == "ZCode/9.9.9"

    async def test_fresh_cache_short_circuits_network(self, tmp_path, monkeypatch):
        """缓存新鲜时不该产生任何网络请求。"""
        monkeypatch.setattr(settings, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(constants, "_CLIENT_APP_VERSION", "1.0.0")
        uv.write_cache("3.14.3")

        def handler(request):  # pragma: no cover - 走到这里就是失败
            raise AssertionError("缓存命中时不应发起网络请求")

        real = httpx.AsyncClient
        monkeypatch.setattr(uv.httpx, "AsyncClient",
                            lambda **kw: real(transport=httpx.MockTransport(handler)))

        assert await uv.refresh() == "3.14.3"
        assert constants.CLIENT_APP_VERSION == "3.14.3"
