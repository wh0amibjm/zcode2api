"""验证码预解池的吞吐不变量（2026-09-28 首 token 延迟优化）。

背景：补货原先是**串行**的（注释给的理由是「求解有 CPU 开销」，但实测单次求解
8~10s 挂钟只烧 ~0.05s CPU，是 IO 等待型），而 token TTL 只有 95s —— 串行补 20 枚
要 200s+，第一批还没补完就过期了，池子长期贴在 0，于是每个请求都退回「同步现解」，
首 token 多出 10~60s（线上实测首字节中位 2781ms、最大 61839ms）。

本文件钉三条：
  1. 补货是并发的（并发度受信号量限制，不是无界爆 Node 进程）
  2. 池空时同批请求**共享一轮补货**，不是各自起 Node 进程
  3. 池空且求解失败时，等待有上界（不会把请求吊死）
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app import settings
from app.captcha import CaptchaManager, CaptchaSolveError, _Token


def _mgr(solve_delay: float = 0.25, ok: bool = True) -> tuple[CaptchaManager, list]:
    """构造一个只走假求解器的 CaptchaManager，返回 (mgr, 求解调用记录)。"""
    mgr = CaptchaManager()
    calls: list[float] = []
    inflight = {"n": 0, "max": 0}

    async def fake_config() -> dict:
        return {"sceneId": "s", "region": "cn", "prefix": "p"}

    async def fake_solve(config: dict):
        calls.append(time.monotonic())
        inflight["n"] += 1
        inflight["max"] = max(inflight["max"], inflight["n"])
        try:
            await asyncio.sleep(solve_delay)
        finally:
            inflight["n"] -= 1
        return _Token(f"param-{len(calls)}", "cn") if ok else None

    mgr.fetch_config = fake_config          # type: ignore[method-assign]
    mgr._solve_one = fake_solve             # type: ignore[method-assign]
    return mgr, calls, inflight             # type: ignore[return-value]


def test_refill_batch_solves_concurrently(monkeypatch):
    """6 枚并发补货的总耗时 ≈ 单枚耗时，而不是 6 倍。"""
    monkeypatch.setattr(settings, "CAPTCHA_SOLVE_CONCURRENCY", 6)
    mgr, calls, inflight = _mgr(solve_delay=0.25)

    t0 = time.monotonic()
    asyncio.run(mgr._refill_batch(6))
    elapsed = time.monotonic() - t0

    assert len(calls) == 6
    assert mgr.stats()["pool_size"] == 6
    assert inflight["max"] <= 6
    assert elapsed < 0.25 * 4, f"补货没并发：6 枚花了 {elapsed:.2f}s"


def test_solve_concurrency_is_capped(monkeypatch):
    """并发度受信号量限制（实例级），不会一次起满 20 个 Node 进程。"""
    monkeypatch.setattr(settings, "CAPTCHA_SOLVE_CONCURRENCY", 3)
    mgr, calls, inflight = _mgr(solve_delay=0.2)

    asyncio.run(mgr._refill_batch(9))

    assert len(calls) == 9          # 全部被解出来
    assert inflight["max"] <= 3     # 但同时刻最多 3 路


def test_cold_pool_waiters_share_one_batch(monkeypatch):
    """池空时 N 个并发请求共享一轮补货：求解次数是一批（并发度），不是 N 个独立进程。"""
    monkeypatch.setattr(settings, "CAPTCHA_SOLVE_CONCURRENCY", 4)
    monkeypatch.setattr(settings, "CAPTCHA_COLD_WAIT", 10)
    mgr, calls, inflight = _mgr(solve_delay=0.3)

    async def scenario():
        return await asyncio.gather(*(mgr.get_verify_param() for _ in range(3)))

    tokens = asyncio.run(scenario())

    assert len(tokens) == 3
    assert all(t[0].startswith("param-") for t in tokens)
    # 一批补 4 枚（并发度），3 个请求各自取走一枚，剩 1 枚留给下一个请求
    assert len(calls) == 4, f"同批请求各起了一批：求解 {len(calls)} 次"
    assert mgr.stats()["pool_size"] == 1


def test_cold_pool_second_request_reuses_remaining_token(monkeypatch):
    """补货剩下的 token 直接服务下一个请求 —— 这是热路径的来源。"""
    monkeypatch.setattr(settings, "CAPTCHA_SOLVE_CONCURRENCY", 4)
    monkeypatch.setattr(settings, "CAPTCHA_COLD_WAIT", 10)
    mgr, calls, _ = _mgr(solve_delay=0.3)

    async def scenario():
        first = await mgr.get_verify_param()
        t0 = time.monotonic()
        second = await mgr.get_verify_param()
        return first, second, time.monotonic() - t0

    _, _, gap = asyncio.run(scenario())

    assert gap < 0.05, f"第二枚没走池子（等了 {gap:.2f}s）"
    assert len(calls) == 4  # 只补了那一批


def test_cold_pool_failure_raises_within_bound(monkeypatch):
    """求解全失败：在 CAPTCHA_COLD_WAIT 内抛错，不吊死客户端。"""
    monkeypatch.setattr(settings, "CAPTCHA_SOLVE_CONCURRENCY", 2)
    monkeypatch.setattr(settings, "CAPTCHA_COLD_WAIT", 1)
    mgr, _calls, _ = _mgr(solve_delay=0.1, ok=False)

    t0 = time.monotonic()
    with pytest.raises(CaptchaSolveError):
        asyncio.run(mgr.get_verify_param())
    assert time.monotonic() - t0 < 3
    assert mgr.stats()["solve_failures"] == 1
    assert mgr.stats()["refill_inflight"] is False


def test_expired_tokens_are_skipped(monkeypatch):
    """池内过期 token 不交付（TTL 95s，过期件只会换来 3007 挑战）。"""
    mgr, _calls, _ = _mgr()
    stale = _Token("stale", "cn")
    stale.born_at = time.monotonic() - 999
    mgr._put(stale)
    fresh = _Token("fresh", "cn")
    mgr._put(fresh)

    token = mgr._take_ready()
    assert token is not None and token.param == "fresh"
    assert mgr._take_ready() is None


def test_evict_expired_keeps_pool_accounting_consistent():
    """淘汰过期件后池账目对齐（_pool_size 与实际可取数一致）。"""
    mgr, _calls, _ = _mgr()
    for i in range(3):
        t = _Token(f"old-{i}", "cn")
        t.born_at = time.monotonic() - 999
        mgr._put(t)
    mgr._put(_Token("live", "cn"))

    asyncio.run(mgr._evict_expired())

    assert mgr.stats()["pool_size"] == 1
    assert len(mgr._pool._queue) == 1  # noqa: SLF001 - 直接核对队列本身
    assert mgr._take_ready().param == "live"
    assert mgr.stats()["pool_size"] == 0
