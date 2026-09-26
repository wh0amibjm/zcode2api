"""Plan 通道（start-plan）请求头形态锁定 —— 2026-09-27 3012 事故回归。

事故经过与结论见 `docs/development/05-upstream-protocols.md` §9「事故档案（脱敏）」：
曾给 Plan 通道加上游归因头 `x-session-id` / `x-query-id`（当时的理由：官方开源 CLI
对每个模型请求都发这两个头），上线后账号池在数分钟内大面积吃到
`3012 unusual activity`（HTTP 405），`Account.ban_for_risk()` 置 DISABLED，
而该分支按设计**不自动恢复** → 已回滚。

本文件锁定的**不是某次改动的 diff**，而是 Plan 通道自始至今的头形态这一不变量：

- 追踪头恒为 `x-request-id` / `x-zcode-session-type` / `x-zcode-trace-id` 三个；
- 下游塞进来的 `x-session-id` / `x-query-id` 必须被丢弃（`agent._DROP_HEADERS`）；
- 集成层再确认一次：**上游实际收到的头**里没有这两个（不只看网关的构造结果）。

要往这三行里加第四个追踪头之前，先读 §9 —— 上游把这两个头当异常信号，
不是可自由启用的缓存钥匙；「官方实现发了」不构成「本网关可以发」的依据。
"""

from __future__ import annotations

import base64
import json

import pytest

from app.agent import build_request
from app.identity import build_trace_headers
from app.models import Account

# 事故头：Plan 通道发往上游的请求里任何情况下都不得出现
INCIDENT_HEADERS = ("x-session-id", "x-query-id")
# Plan 通道的追踪头三件套（缺失任一即形态不符）
PLAN_TRACE_HEADERS = ("x-request-id", "x-zcode-session-type", "x-zcode-trace-id")


def _fake_jwt() -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u-1"}).encode()).rstrip(b"=").decode()
    return f"h.{payload}.sig"


def _plan_account() -> Account:
    return Account(id="x", name="x", provider="zai", mode="jwt", jwt_token=_fake_jwt())


def _build(account: Account | None = None, incoming: dict | None = None):
    body = {"model": "GLM-5.3", "messages": [{"role": "user", "content": "hi"}]}
    return build_request(account or _plan_account(), body, None, incoming or {})


def _lower(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


class TestPlanChannelTraceHeaderShape:
    """单测层：网关构造出的头（未出网即可断言）。"""

    def test_incident_headers_absent(self):
        """事故头不得出现在 Plan 通道（本组用例存在的唯一理由）。"""
        for incoming in (None, {"x-session-id": "downstream-sess", "x-query-id": "q-1"}):
            lower = _lower(_build(incoming=incoming)[1])
            for name in INCIDENT_HEADERS:
                assert name not in lower, f"Plan 通道发了事故头 {name}（见 docs/development/05 §9）"

    def test_trace_header_trio_present(self):
        lower = _lower(_build()[1])
        for name in PLAN_TRACE_HEADERS:
            assert name in lower, f"Plan 通道缺追踪头 {name}"

    def test_trace_headers_per_request_fresh(self):
        """HEAD 行为：三个头里 request/trace 每请求新值（会话级稳定是事故修法，未采纳）。"""
        _, h1, _ = _build()
        _, h2, _ = _build()
        assert h1["x-request-id"] != h2["x-request-id"]
        assert h1["x-zcode-trace-id"] != h2["x-zcode-trace-id"]
        assert h1["x-zcode-session-type"] == h2["x-zcode-session-type"] == "main"

    def test_downstream_incident_headers_dropped(self):
        """下游伪造的事故头必须被剔除，不能靠"客户端不发"来保证。"""
        lower = _lower(_build(incoming={
            "x-session-id": "spoofed-sess",
            "X-Session-Id": "spoofed-sess-2",
            "x-query-id": "spoofed-q",
        })[1])
        for name in INCIDENT_HEADERS:
            assert name not in lower, name

    def test_apikey_channel_has_no_trace_headers(self):
        """API Key 回退通道保持最小头集：追踪头整族都不该出现。"""
        acc = Account(id="k", name="k", provider="zai", mode="apiKey", api_key="sk-test")
        lower = _lower(_build(account=acc)[1])
        for name in PLAN_TRACE_HEADERS + INCIDENT_HEADERS:
            assert name not in lower, name


class TestCodingPlanBranchKeepsItsShape:
    """`plan="coding-plan"` 分支仍发 x-query-id / x-session-id（zapi 记录的 API Key 通道形态）。

    修事故时**别把这条一起删掉**：通道差异是既有结论，事故只推翻了"start-plan 也发"。
    本用例是那条差异的反向锁 —— 若将来要统一头形态，先改这里并在 §9 记一笔。
    """

    def test_coding_plan_branch_still_sends_them(self):
        h = {k.lower(): v for k, v in build_trace_headers(plan="coding-plan").items()}
        assert "x-session-id" in h and h["x-session-id"]
        assert "x-query-id" in h and h["x-query-id"]

    def test_start_plan_branch_does_not(self):
        h = {k.lower(): v for k, v in build_trace_headers(plan="start-plan").items()}
        assert set(h) == set(PLAN_TRACE_HEADERS)


# ── 集成层：上游实际收到的头（Mock 上游记录 app.state.calls）─────────────────
@pytest.mark.integration
class TestUpstreamObservedHeaderShape:
    """走完整网关链路后，断言**上游侧**观察到的头 —— 与生产行为同形（真实 TCP）。"""

    async def _post(self, client, headers=None):
        return await client.post(
            "/v1/messages",
            json={"model": "glm-5.2", "messages": [{"role": "user", "content": "hi"}]},
            headers=headers or {},
        )

    async def test_upstream_sees_no_incident_headers(self, gateway_client):
        client, upstream = gateway_client
        from app.store import store
        store.add_account("zai", "t", "h1.eyJzdWIiOiJhIn0.sig")

        assert (await self._post(client)).status_code == 200
        _, path, headers, _ = upstream.state.calls[-1]
        assert path == "/api/v1/zcode-plan/anthropic/v1/messages"
        for name in INCIDENT_HEADERS:
            assert name not in headers, f"上游收到了事故头 {name}（见 docs/development/05 §9）"
        for name in PLAN_TRACE_HEADERS:
            assert name in headers, f"上游缺追踪头 {name}"

    async def test_downstream_session_headers_never_reach_upstream(self, gateway_client):
        client, upstream = gateway_client
        from app.store import store
        store.add_account("zai", "t", "h1.eyJzdWIiOiJhIn0.sig")

        res = await self._post(client, headers={
            "x-session-id": "downstream-sess",
            "x-query-id": "downstream-q",
        })
        assert res.status_code == 200
        headers = upstream.state.calls[-1][2]
        for name in INCIDENT_HEADERS:
            assert name not in headers, f"下游提供的事故头透传到了上游: {name}"
