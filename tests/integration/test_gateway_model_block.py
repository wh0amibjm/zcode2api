"""3012 判级 + 模型级熔断（2026-09-28 实证）。

线上事实：start-plan 通道上 GLM-5.3 稳定 405+3012，同账号几秒后的 GLM-5.3-Flash
正常 200（顺序无关）。原实现把 3012 一律当**账号级**风控 → 每个 GLM-5.3 请求
禁用掉一个账号，03:10–03:15 五个请求抽干 20 个号。

本文件钉住四条不变量：
  1. 模型级 3012：账号**不**被禁用，模型被熔断，客户端拿到 400 model_blocked
  2. 熔断期内同模型请求在 _dispatch 就被拦下 —— 零上游流量、零验证码消耗
  3. 同账号的其它模型照常服务（熔断是模型维度，不是账号维度）
  4. 账号级 3012（探针同样被拦）仍然封号；判级无据时冷却而不封号
"""

from __future__ import annotations

import json

import pytest

from app import settings
from app.models import Status

ADMIN_AUTH = {"Authorization": "Bearer zcode"}  # 默认后台密钥

_BLOCKED_BODY = {"model": "GLM-5.3", "messages": [{"role": "user", "content": "hi"}]}
_FLASH_BODY = {"model": "GLM-5.3-Flash", "messages": [{"role": "user", "content": "hi"}]}


def _jwt(tag: str) -> str:
    """每条用例一个独立凭证。

    mock 的调用计数器是 session 级的（按凭证前缀绑定），复用同一个 JWT 会让后一条
    用例从 x-mock-sequence 的中间开始消费 —— 症状是「第一条请求就不是 3012」。
    """
    return (tag + "0000000000000000")[:16] + ".eyJzdWIiOiIzIn0.sig"


def _sent_models(mock):
    """上游实际收到的 model 序列（判级探针的取证）。"""
    out = []
    for call in mock.state.calls:
        if not call[1].endswith("/messages"):
            continue
        try:
            out.append(json.loads(call[3]).get("model"))
        except (ValueError, TypeError):
            pass
    return out


@pytest.mark.integration
class TestModelLevel3012:
    async def test_model_3012_does_not_ban_account(self, gateway_client, fresh_app):
        """探针证明账号健康 ⇒ 熔断模型、账号保持可用（线上被误杀的那种号）。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model01")
        acc = seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        before = len(_sent_models(mock))
        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 400
        err = res.json()["error"]
        assert err["type"] == "model_blocked"
        assert err["model"] == "GLM-5.3"

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.ACTIVE     # 关键：没有被禁用
        assert after.enabled is True
        assert after.risk_strikes == 0           # 关键：没有记风控
        assert after.is_selectable() is True
        assert "模型级拦截" in (after.last_error or "")

        # 判级探针确实发出去了，而且用的是 Flash（原请求 + 探针 = 2 次）
        assert _sent_models(mock)[before:] == ["GLM-5.3", "GLM-5.3-Flash"]

    async def test_block_short_circuits_without_upstream_traffic(self, gateway_client, fresh_app):
        """熔断期内再打同模型：_dispatch 直接拒绝，不打上游、不烧验证码。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model02")
        seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        assert (await client.post("/v1/messages", json=_BLOCKED_BODY)).status_code == 400
        before = len(mock.state.calls)

        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 400
        assert res.json()["error"]["type"] == "model_blocked"
        assert len(mock.state.calls) == before  # 零上游流量

        # 账号也没被动过（熔断不是账号状态）
        acc = fresh_app.list_accounts("zai")[0]
        assert acc.status == Status.ACTIVE
        assert acc.risk_strikes == 0
        assert acc.fail_count == 1  # 只记了第一次那笔失败

    async def test_other_models_still_served(self, gateway_client, fresh_app):
        """熔断是模型维度的：同账号的 Flash 照常 200。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model03")
        seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        assert (await client.post("/v1/messages", json=_BLOCKED_BODY)).status_code == 400

        res = await client.post("/v1/messages", json=_FLASH_BODY)
        assert res.status_code == 200
        acc = fresh_app.list_accounts("zai")[0]
        assert acc.use_count == 1

    async def test_block_is_case_insensitive(self, gateway_client, fresh_app):
        """上游对 glm-5.3 / GLM-5.3 反应一致 ⇒ 熔断键按小写归一，换大小写绕不过去。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model04")
        seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        assert (await client.post("/v1/messages", json=_BLOCKED_BODY)).status_code == 400
        before = len(mock.state.calls)
        res = await client.post(
            "/v1/messages",
            json={"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert res.status_code == 400
        assert res.json()["error"]["type"] == "model_blocked"
        assert len(mock.state.calls) == before

    async def test_admin_can_clear_block(self, gateway_client, fresh_app):
        """后台确认上游恢复后手动解除熔断，无需重启。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model05")
        seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]
        assert (await client.post("/v1/messages", json=_BLOCKED_BODY)).status_code == 400

        res = await client.get("/admin/api/model-blocks", headers=ADMIN_AUTH)
        assert res.status_code == 200
        blocks = res.json()["blocks"]
        assert [b["model"] for b in blocks] == ["glm-5.3"]
        assert blocks[0]["remaining"] > 0

        res = await client.post("/admin/api/model-blocks/clear", headers=ADMIN_AUTH)
        assert res.json()["cleared"] == ["glm-5.3"]

        # 解除后同模型重新打上游（这次 Mock 仍按模型拦，故仍 400 —— 但已重新判级）
        before = len(mock.state.calls)
        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 400
        assert len(mock.state.calls) > before

    async def test_monitoring_surfaces_blocks(self, gateway_client, fresh_app):
        """监控页能看见熔断（否则前端无从解释「为什么这个模型一直 400」）。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("model06")
        seed_account(fresh_app, jwt, name="a-modelblock")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]
        assert (await client.post("/v1/messages", json=_BLOCKED_BODY)).status_code == 400

        body = (await client.get("/admin/api/monitoring", headers=ADMIN_AUTH)).json()
        assert [b["model"] for b in body["model_blocks"]] == ["glm-5.3"]


@pytest.mark.integration
class TestAccountLevel3012StillBans:
    async def test_probe_blocked_too_means_account_ban(self, gateway_client, fresh_app, monkeypatch):
        """探针（Flash）同样 3012 ⇒ 账号自身被盯上，维持原行为：封号待人工复核。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        monkeypatch.setattr(mock.state, "risk_models", {"GLM-5.3", "GLM-5.3-Flash"})
        jwt = _jwt("acct01")
        acc = seed_account(fresh_app, jwt, name="a-hot")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 503  # 唯一账号被封，不空转

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.DISABLED
        assert after.risk_strikes == 1
        assert "风控封禁" in (after.last_error or "")
        # 账号级判级不应产生模型熔断
        blocks = (await client.get("/admin/api/model-blocks", headers=ADMIN_AUTH)).json()["blocks"]
        assert blocks == []

    async def test_probe_disabled_restores_legacy_ban(self, gateway_client, fresh_app, monkeypatch):
        """ZCODE_MODEL_BLOCK_PROBE=0 时退回旧行为（3012 一律封号），便于对比排查。"""
        client, mock = gateway_client
        from tests.conftest import seed_account

        monkeypatch.setattr(settings, "MODEL_BLOCK_PROBE", 0)
        jwt = _jwt("acct02")
        acc = seed_account(fresh_app, jwt, name="a-legacy")
        mock.state.sequences[jwt[:16]] = ["risk_control_3012_by_model"]

        before = len(_sent_models(mock))
        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 503
        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.DISABLED
        assert after.risk_strikes == 1
        # 没发探针：本用例只在上游留下一次调用
        assert _sent_models(mock)[before:] == ["GLM-5.3"]

    async def test_probe_failure_cools_instead_of_banning(self, gateway_client, fresh_app):
        """判级无据（探针吃 5xx）⇒ 冷却待复核，不封号。

        误封不可自愈、误冷却会自愈，所以不确定时的保守方向是冷却 ——
        与「403 不再无条件判 invalid」是同一条既有修正。
        """
        client, mock = gateway_client
        from tests.conftest import seed_account

        jwt = _jwt("acct03")
        acc = seed_account(fresh_app, jwt, name="a-unknown")
        # 第 1 次调用（原请求）3012；第 2 次（探针）5xx → 判级无据
        mock.state.sequences[jwt[:16]] = ["risk_control_3012", "server_error"]

        res = await client.post("/v1/messages", json=_BLOCKED_BODY)
        assert res.status_code == 503

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.COOLING
        assert after.cooling_until is not None
        assert after.risk_strikes == 0
        assert after.enabled is True
        assert "判级无据" in (after.last_error or "")


@pytest.mark.integration
class TestRiskResetEndpoint:
    async def test_risk_reset_revives_banned_accounts(self, gateway_client, fresh_app):
        """批量复位风控封禁（操作 3 的 API 形态）：清 strikes、回 ACTIVE。"""
        client, _mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _jwt("reset01"), name="a-banned")
        acc.ban_for_risk()
        acc.last_error = "风控封禁 (3012/unusual activity) HTTP 405，确认恢复后请在后台手动启用（第 1 次）"
        fresh_app.update_account(acc)

        res = await client.post("/admin/api/accounts/risk-reset", json={}, headers=ADMIN_AUTH)
        assert res.status_code == 200
        assert res.json()["reset"] == ["a-banned"]

        after = fresh_app.find("zai", acc.id)
        assert after.status == Status.ACTIVE
        assert after.risk_strikes == 0
        assert after.last_error is None
        assert after.is_selectable() is True

    async def test_risk_reset_leaves_manually_disabled_alone(self, gateway_client, fresh_app):
        """manual enable=False 的账号不是风控封禁，复位动作不得顺手打开它。"""
        client, _mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _jwt("reset02"), name="a-manual-off")
        fresh_app.set_enabled("zai", acc.id, False)

        res = await client.post("/admin/api/accounts/risk-reset", json={}, headers=ADMIN_AUTH)
        assert res.json()["reset"] == []
        after = fresh_app.find("zai", acc.id)
        assert after.enabled is False
        assert after.status == Status.DISABLED

    async def test_risk_reset_by_ids_skips_others(self, gateway_client, fresh_app):
        client, _mock = gateway_client
        from tests.conftest import seed_account

        a1 = seed_account(fresh_app, _jwt("reset03"), name="a-one")
        a2 = seed_account(fresh_app, _jwt("reset04"), name="a-two")
        a1.ban_for_risk()
        a2.ban_for_risk()
        fresh_app.update_account(a1)
        fresh_app.update_account(a2)

        res = await client.post("/admin/api/accounts/risk-reset",
                                json={"ids": [a1.id]}, headers=ADMIN_AUTH)
        assert res.json()["reset"] == ["a-one"]
        assert fresh_app.find("zai", a1.id).status == Status.ACTIVE
        assert fresh_app.find("zai", a2.id).status == Status.DISABLED
