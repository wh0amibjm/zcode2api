"""活动自动领取轮询（ClaimMonitor）的行为用例。

为什么要这个轮询：基座的自动领取只在**入池那一刻**跑一次，而活动是**分批投放**的 ——
2026-09-26 实测同一个账号的 preview 先只有 `zcode-v3-start-plan-0926`（1 亿），
十几分钟后才出现 `zcode-v3-start-plan-0924-wk-2`（周末场 3 亿）。没有周期检查，
后续场次就得人工去后台点。

这里钉住三条边界：只挑合规账号、单账号异常不拖垮整轮、间隔为 0 时不产生任何上游流量。
"""

from __future__ import annotations

from app import claim as claim_mod
from app import settings
from app.claim import ClaimMonitor
from app.models import Status


def _mk(store, secret: str, name: str, mode_jwt: bool = True, status: str = Status.ACTIVE):
    """造一个账号；jwt 用三段式构造串（非真实凭证）。"""
    acc = store.add_account("zai", name, f"h.{secret}.sig" if mode_jwt else f"sk-{secret}")
    acc.status = status
    store.update_account(acc)
    return acc


class TestClaimMonitorRound:
    async def test_only_billing_allowed_jwt_accounts(self, fresh_app, monkeypatch):
        """apiKey 账号与风控禁用账号都不产生领取流量。"""
        called: list[str] = []

        async def fake_claim(acc):
            called.append(acc.name)
            return []

        monkeypatch.setattr(claim_mod, "auto_claim_all_plans", fake_claim)
        monkeypatch.setattr(settings, "CLAIM_STAGGER", 0)

        _mk(fresh_app, "eyJzdWIiOiJhIn0", "a-jwt")
        _mk(fresh_app, "key-b", "b-apikey", mode_jwt=False)
        _mk(fresh_app, "eyJzdWIiOiJjIn0", "c-banned", status=Status.DISABLED)

        attempted = await ClaimMonitor().run_once()

        assert called == ["a-jwt"]
        assert attempted == ["a-jwt"]

    async def test_one_account_failure_does_not_stop_the_round(self, fresh_app, monkeypatch):
        """一个账号抛异常，后面的账号仍要被处理。"""
        seen: list[str] = []

        async def flaky(acc):
            seen.append(acc.name)
            if acc.name == "a-boom":
                raise RuntimeError("upstream exploded")
            return []

        monkeypatch.setattr(claim_mod, "auto_claim_all_plans", flaky)
        monkeypatch.setattr(settings, "CLAIM_STAGGER", 0)

        _mk(fresh_app, "eyJzdWIiOiJhIn0", "a-boom")
        _mk(fresh_app, "eyJzdWIiOiJiIn0", "b-ok")

        attempted = await ClaimMonitor().run_once()

        assert seen == ["a-boom", "b-ok"]
        assert attempted == ["b-ok"]        # 抛异常的那个不算尝试成功

    async def test_zero_interval_produces_no_upstream_traffic(self, fresh_app, monkeypatch):
        """CLAIM_INTERVAL=0 时循环体不跑 —— 关掉就必须一个请求都不发。"""
        called: list[str] = []

        async def fake_claim(acc):
            called.append(acc.name)
            return []

        monkeypatch.setattr(claim_mod, "auto_claim_all_plans", fake_claim)
        monkeypatch.setattr(settings, "CLAIM_INTERVAL", 0)
        monkeypatch.setattr(settings, "CLAIM_START_DELAY", 0)

        _mk(fresh_app, "eyJzdWIiOiJhIn0", "a-jwt")

        mon = ClaimMonitor()
        mon.start()
        import asyncio
        await asyncio.sleep(0.05)
        await mon.stop()

        assert called == []
