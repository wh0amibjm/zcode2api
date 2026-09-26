"""挑战处置与热路径落库的回归（2026-09-27 吞吐调优）。

实验依据 experiments/probe_3007_isolation.py：
- 3007 只打提出它的那一枚 token（坏枚被拒后，紧接着用新枚请求 200 通过）；
- verifyParam 一次性（同一枚 30s 后复用即 3007）。
因此默认单枚失效；连续挑战之间没有任何成功才升级全清（保留旧 invalidate
的保守面）。落库侧：成功路径 use_count 类计数走 touch_account 脏标记延刷，
状态类变更仍即时落。
"""

from __future__ import annotations

from app.captcha import CaptchaManager, _Token
from app.store import Store


def _prime(mgr: CaptchaManager, params: list[str]) -> list[_Token]:
    tokens = [_Token(p, None) for p in params]
    for token in tokens:
        mgr._put(token)
    return tokens


def _drain(mgr: CaptchaManager) -> list[str]:
    out: list[str] = []
    while True:
        token = mgr._take()
        if token is None:
            return out
        out.append(token.param)


class TestOnChallenge:
    def test_single_challenge_evicts_only_offending_token(self):
        mgr = CaptchaManager()
        tokens = _prime(mgr, ["a", "b", "c"])
        mgr.on_challenge(tokens[1])
        assert mgr._pool_size == 2
        assert _drain(mgr) == ["a", "c"]        # FIFO 原序保留，只少了 b

    def test_consecutive_challenges_without_accept_escalate_to_full_wipe(self):
        mgr = CaptchaManager()
        tokens = _prime(mgr, ["a", "b", "c"])
        mgr.on_challenge(tokens[0])              # 第 1 次：单枚失效
        assert mgr._pool_size == 2
        mgr.on_challenge(_Token("x", None))      # 第 2 次：升级全清（旧行为）
        assert mgr._pool_size == 0

    def test_accept_between_challenges_keeps_single_evict_policy(self):
        mgr = CaptchaManager()
        tokens = _prime(mgr, ["a", "b", "c"])
        mgr.on_challenge(tokens[0])
        mgr.note_accept()                        # 上游正常消费了一枚
        mgr.on_challenge(tokens[2])
        assert _drain(mgr) == ["b"]              # 仍是单枚失效，没有升级

    def test_challenge_token_not_in_pool_is_noop_evict(self):
        mgr = CaptchaManager()
        _prime(mgr, ["a", "b"])
        mgr.on_challenge(_Token("ghost", None))
        assert _drain(mgr) == ["a", "b"]


class TestAcquireToken:
    async def test_pooled_token_returned_as_object(self, monkeypatch):
        """池有货时 acquire_token 返回池内 token 对象，且不触发任何补货动作。"""
        mgr = CaptchaManager()

        async def _no_refill(floor: int = 0) -> int:
            return 0

        monkeypatch.setattr(mgr, "_refill_once", _no_refill)
        monkeypatch.setattr(mgr, "_kick_refill", lambda: None)
        _prime(mgr, ["p1"])
        token = await mgr.acquire_token()
        assert token.param == "p1"
        assert token.region is None


class TestTouchAccount:
    def test_counts_deferred_until_flush(self, fresh_app):
        acc = fresh_app.add_account("zai", "a", "jwt.touch.a")
        fresh_app.flush_dirty()                  # 清掉入池时的即时落库
        acc.use_count = 7
        fresh_app.touch_account(acc)
        assert Store().find("zai", acc.id).use_count == 0   # 未刷：盘上还是 0
        fresh_app.flush_dirty()
        assert Store().find("zai", acc.id).use_count == 7   # 刷后落盘

    def test_touch_refuses_deleted_account(self, fresh_app):
        acc = fresh_app.add_account("zai", "b", "jwt.touch.b")
        aid = acc.id
        assert fresh_app.remove_account("zai", aid)
        acc.use_count = 9
        fresh_app.touch_account(acc)             # 不得抛错
        fresh_app.flush_dirty()                  # 不得把已删行写回
        assert fresh_app.find("zai", aid) is None
        assert Store().find("zai", aid) is None

    def test_flush_with_no_dirty_is_noop(self, fresh_app):
        fresh_app.flush_dirty()                  # 空刷不炸、不写库
