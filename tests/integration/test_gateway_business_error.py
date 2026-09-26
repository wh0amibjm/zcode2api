"""GW-011 HTTP 200 里的业务错误码（2026-09-26 线上实测形态）。

start-plan（JWT）通道额度耗尽时上游回的**不是 4xx**：

    HTTP/1.1 200 OK · content-type: application/json
    {"code":1005,"msg":"exceed quota limit","logid":"…"}

只按 `status_code >= 400` 判失败的写法会把它当成功：recent_results 记 ok=True、
账号不换、客户端收到「200 但内容不是 message」的响应，而额度回来那天也没有任何
东西知道。修法是把业务码归一化成等效状态码（额度→402 / 风控→405 / 验证码→400 /
未知→502），复用既有的 4xx 分支。

本文件钉住四件事：
  1. 200+1005 不再被计成成功（use_count / recent_results）
  2. 200+1005 会把账号标成 EXHAUSTED 且换到下一个可用账号
  3. 归一化后仍无可用账号 → 503（客户端的诚实失败，不是假 200）
  4. **正常**的非流式 JSON 响应体经嗅探后仍完整送达（预读不得吞体）
"""

from __future__ import annotations

import time

import pytest

from app import settings
from app.models import Status

_MSG_BODY = {"model": "GLM-5.3-Flash", "messages": [{"role": "user", "content": "hi"}]}

_JWT_A = "hA.eyJzdWIiOiJhIn0.sig"
_JWT_B = "hB.eyJzdWIiOiJiIn0.sig"
# 未被任何 sequences 喂过的凭证：mock 的 scenario 队列是粘性的（idx 被 clamp 到
# 末位），复用前缀会让「应成功」的用例继续吃上一个用例设的错误序列。
_JWT_C = "hC.eyJzdWIiOiJjIn0.sig"
_JWT_D = "hD.eyJzdWIiOiJkIn0.sig"
_JWT_E = "hE.eyJzdWIiOiJlIn0.sig"
_JWT_F = "hF.eyJzdWIiOiJmIn0.sig"


def _bind(secret: str) -> str:
    return secret[:16]


@pytest.mark.integration
class TestBusinessErrorIn200:
    async def test_normal_json_body_survives_sniffing(self, gateway_client, fresh_app):
        """嗅探预读不得吞掉正常响应体（非流式 JSON 成功路径的回归）。"""
        client, _mock = gateway_client
        from tests.conftest import seed_account

        # 用未被任何 sequences 喂过的 _JWT_F：本用例若复用 _JWT_A，就依赖"文件内
        # 先于写序列的用例执行"这一顺序 —— 随机序 / -k 子集下会吃到粘滞的错误序列。
        seed_account(fresh_app, _JWT_F, name="a-ok")

        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 200
        data = res.json()
        assert data.get("type") == "message"
        assert data.get("content") and data["content"][0]["text"]
        assert data.get("usage", {}).get("output_tokens") == 5

    async def test_quota_exceeded_200_switches_account(self, gateway_client, fresh_app):
        """一号回 200+1005，请求应落到二号并成功；一号被标 EXHAUSTED。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        acc_a = seed_account(fresh_app, _JWT_A, name="a-quota")
        seed_account(fresh_app, _JWT_B, name="b-ok")
        mock.state.sequences[_bind(_JWT_A)] = ["quota_exceeded_200"]

        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 200, res.text
        assert res.json().get("type") == "message"

        after = fresh_app.find("zai", acc_a.id)
        assert after.status == Status.EXHAUSTED
        # 计费口径：假成功不得进 use_count，最近结果要留一条失败
        assert after.use_count == 0
        assert after.recent_results
        assert after.recent_results[-1]["ok"] is False
        assert "额度" in after.recent_results[-1]["detail"] or "402" in after.recent_results[-1]["detail"]

    async def test_quota_exceeded_200_sets_retry_window(self, gateway_client, fresh_app, monkeypatch):
        """EXHAUSTED 必须带试探窗口：上游额度是日窗口，billing 又可能回落成空数组。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        monkeypatch.setattr(settings, "EXHAUST_RETRY_SECONDS", 1200)
        acc = seed_account(fresh_app, _JWT_A, name="a-window")
        mock.state.sequences[_bind(_JWT_A)] = ["quota_exceeded_200"]

        before = time.time()
        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 503  # 无别的号可换 → 诚实失败

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.EXHAUSTED
        assert after.exhausted_until is not None
        assert after.exhausted_until >= before + 1200 - 5
        # 窗口内不可选；到期后放回池子（额度恢复由「成功即复活」收口）
        assert after.is_selectable() is False
        assert after.is_selectable(after.exhausted_until + 1) is True

    async def test_quota_exceeded_200_is_not_a_success_tick(self, gateway_client, fresh_app):
        """单号场景：客户端拿到 503 而不是 200，账号 use_count 不涨。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _JWT_A, name="a-only")
        mock.state.sequences[_bind(_JWT_A)] = ["quota_exceeded_200"]

        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 503
        body = res.json()
        assert body.get("error", {}).get("type") == "no_available_account"

        after = fresh_app.find("zai", acc.id)
        assert after.use_count == 0
        assert after.status == Status.EXHAUSTED

    async def test_expired_window_lets_account_recover(self, gateway_client, fresh_app):
        """额度试探窗到期 → 账号自动回到池子；这一轮成功即复活（无需人工干预）。

        这是「额度是日窗口、且 billing 在耗尽时回落成空数组」的唯一兜底：没有这条
        闭环，额度回来了账号也不会被选中。
        """
        client, _mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _JWT_C, name="a-recover")
        acc.status = Status.EXHAUSTED
        acc.exhausted_until = time.time() - 1        # 窗口刚过期 = 额度可能已恢复
        acc.last_error = "额度已用完"
        fresh_app.update_account(acc)

        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 200, res.text
        assert res.json().get("type") == "message"

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.ACTIVE
        assert after.exhausted_until is None
        assert after.last_error is None

    async def test_unexpired_window_keeps_account_out(self, gateway_client, fresh_app):
        """窗口未到期 → 不产生任何上游流量（这是 EXHAUSTED 的原语义，不能因为加窗丢失）。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _JWT_D, name="a-hold")
        acc.status = Status.EXHAUSTED
        acc.exhausted_until = time.time() + 600
        fresh_app.update_account(acc)

        before = len(mock.state.calls)
        res = await client.post("/v1/messages", json=_MSG_BODY)
        assert res.status_code == 503
        assert len(mock.state.calls) == before      # 一个上游请求都没发
        assert fresh_app.find("zai", acc.id).status == Status.EXHAUSTED

    async def test_stream_request_also_sees_business_error(self, gateway_client, fresh_app):
        """流式请求遇 200+业务码：线上实测上游回的是 JSON 而非 SSE，嗅探必须覆盖。

        只按 stream 标志跳过嗅探的实现会在这里漏判成假成功。
        """
        client, mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _JWT_E, name="a-stream")
        mock.state.sequences[_bind(_JWT_E)] = ["quota_exceeded_200"]

        res = await client.post("/v1/messages", json={**_MSG_BODY, "stream": True})
        assert res.status_code == 503, res.text
        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.EXHAUSTED
        assert after.use_count == 0
        assert after.recent_results[-1]["ok"] is False
