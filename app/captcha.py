"""验证码求解 + 预解 token 池。

通过 Node 子进程在 happy-dom 模拟浏览器环境中运行阿里云无痕 SDK，
求得 verifyParam（X-Aliyun-Captcha-Verify-Param）。

架构对齐 zapi captcha.ts 的预解池设计：
- 热路径永不等待：请求到来时直接从池里取一枚已解好的 token（亚毫秒），
  后台任务持续补充库存（目标 min，上限 max）。
- token 时效：verifyParam 实际 TTL ~2 分钟，池内按 FIFO + 年龄淘汰，
  超过 token_ttl 的直接丢弃重解。
- 挑战失效：上游返回挑战时 invalidate() 清空整池（该批指纹可能已被
  风控盯上，继续复用只会连环 3007）。
"""

from __future__ import annotations

import asyncio
import time

import httpx

from . import constants, logs, settings
from .store import store

# 池参数（对齐 zapi：min 20-40 / max 120 过重，单账号网关用小池足矣）
POOL_MIN = settings.CAPTCHA_POOL_MIN
POOL_MAX = settings.CAPTCHA_POOL_MAX
TOKEN_TTL_MS = settings.CAPTCHA_TOKEN_TTL  # 单枚 token 的最大可用时长（ms）


class CaptchaSolveError(Exception):
    """验证码求解最终失败（重试耗尽/求解器不可用）。

    独立于 ClaimError 体系（验证码先于领域层使用），路由层按兜底回执处理。
    """


class _Token:
    __slots__ = ("param", "region", "born_at")

    def __init__(self, param: str, region: str | None) -> None:
        self.param = param
        self.region = region
        self.born_at = time.monotonic()

    def expired(self) -> bool:
        return (time.monotonic() - self.born_at) * 1000 >= TOKEN_TTL_MS


class CaptchaManager:
    def __init__(self) -> None:
        self._pool: asyncio.Queue[_Token] = asyncio.Queue(maxsize=POOL_MAX)
        self._pool_size = 0          # Queue 无可信 len，自行维护
        self._refill_task: asyncio.Task | None = None
        # 补货锁：同一时刻只有一批在跑（批次内部才是并发的）。hot path 与后台循环
        # 都从这里进，因此不会出现「N 个请求各解一枚」的进程风暴。
        self._refill_lock = asyncio.Lock()
        # 并发度信号量：**实例级**（按批新建等于没限流，每批都拿到全新额度）
        self._solve_sem = asyncio.Semaphore(max(1, settings.CAPTCHA_SOLVE_CONCURRENCY))
        self._batch_inflight = False
        self._solved_total = 0
        self._solve_failures = 0
        self._config_lock = asyncio.Lock()
        self._config_cache: dict | None = None
        self._config_cache_at: float = 0.0
        self._last_error: str | None = None
        # 热路径触发的补货任务强引用（事件循环只持弱引用，裸 create_task 会被 GC）
        self._bg_tasks: set[asyncio.Task] = set()

    # ── 配置 ─────────────────────────────────────────────────────────────────
    async def fetch_config(self) -> dict:
        now = time.time() * 1000
        if self._config_cache and now - self._config_cache_at < settings.CAPTCHA_CONFIG_CACHE_TTL:
            return self._config_cache
        async with self._config_lock:
            # 双检：等锁期间可能已被其他请求填充
            if self._config_cache and time.time() * 1000 - self._config_cache_at < settings.CAPTCHA_CONFIG_CACHE_TTL:
                return self._config_cache
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    res = await client.get(
                        f"{constants.CLIENT_CONFIGS_URL}?{constants.CLIENT_CONFIGS_QUERY}"
                    )
                res.raise_for_status()
                captcha = ((res.json().get("data") or {}).get("configs") or {}).get("captcha")
                if captcha:
                    self._config_cache = captcha
                    self._config_cache_at = time.time() * 1000
                    return captcha
            except (httpx.HTTPError, ValueError) as err:
                logs.warn("captcha", f"获取配置失败，使用默认: {err}")
            return dict(constants.CAPTCHA_DEFAULTS)

    # ── 预解池 ───────────────────────────────────────────────────────────────
    def start(self) -> None:
        """启动后台补充循环（main.py lifespan 调用）。"""
        if self._refill_task is None or self._refill_task.done():
            self._refill_task = asyncio.create_task(self._refill_loop())

    async def close(self) -> None:
        if self._refill_task and not self._refill_task.done():
            self._refill_task.cancel()
            try:
                await self._refill_task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001
                pass
        self._refill_task = None

    def _gate_open(self) -> bool:
        """是否允许预热：存在可走 Plan 对话的 jwt 账号才预热。

        apiKey 回退 / 废 JWT / 风控禁用 / 额度用完 / 冷却 都不需要验证码。
        账号冷却状态随 store 落库，重启后全冷却期间此门保持关闭。
        """
        return any(
            a.allows_billing() and a.is_selectable()
            for a in store.list_accounts("zai")
        )

    async def _refill_loop(self) -> None:
        while True:
            try:
                # 无可服务账号（全冷却/禁用/无号）：只淘汰过期 token，不解新码（不产生上游流量）
                if not self._gate_open():
                    await self._evict_expired()
                    await asyncio.sleep(3)
                    continue
                need = POOL_MIN - self._pool_size
                if need > 0:
                    await self._refill_batch(need)
                else:
                    await self._evict_expired()
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - 后台循环永不退出
                self._last_error = str(err)
                logs.warn("captcha", f"补充循环异常: {err}")
                await asyncio.sleep(5)

    async def _refill_batch(self, need: int) -> None:
        """补充一批库存（**并发**求解，同一时刻只有一批在跑）。

        为什么必须并发：单次求解 8~10s 挂钟但只烧 ~0.05s CPU（时间全等在 Node 启动
        与上游校验上，是 IO 型），而 token 自身 TTL 只有 95s —— 串行补 20 枚要 200s+，
        第一批还没补完就已过期，池子永远填不满、长期贴在 0，于是每个请求都退回
        「同步现解」，首 token 平白多出 10~60s。实测首字节中位 2781ms / 最大 61839ms，
        那个 61s 就是池空同步解出来的。

        并发度由 `CAPTCHA_SOLVE_CONCURRENCY`（默认 6）限制；信号量是**实例级**的，
        按批新建等于没限流（每次都是新的 6 个额度）。
        """
        self._batch_inflight = True
        try:
            async with self._refill_lock:
                await self._solve_many(need)
        finally:
            self._batch_inflight = False

    async def _solve_many(self, count: int) -> int:
        """并发求解至多 count 枚（各自入池），返回实际成功枚数。"""
        budget = min(count, max(0, POOL_MAX - self._pool_size))
        if budget <= 0:
            return 0
        config = await self.fetch_config()
        solved = 0

        async def worker() -> None:
            nonlocal solved
            async with self._solve_sem:
                if self._pool_size >= POOL_MAX:
                    return
                token = await self._solve_one(config)
                if token is not None:
                    self._put(token)
                    solved += 1
                else:
                    self._last_error = self._last_error or "求解失败"

        await asyncio.gather(*(worker() for _ in range(budget)))
        if solved:
            logs.ok("captcha", f"补货 {solved} 枚（并发 {budget} 路），池内 {self._pool_size} 枚")
        return solved

    def _take_ready(self) -> _Token | None:
        """从池里取一枚未过期的 token（顺手丢弃取到的过期 token）。"""
        while self._pool_size > 0:
            try:
                token = self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            if not token.expired():
                return token
        return None

    def _put(self, token: _Token) -> None:
        try:
            self._pool.put_nowait(token)
            self._pool_size += 1
            self._solved_total += 1
        except asyncio.QueueFull:
            pass

    async def _evict_expired(self) -> None:
        kept: list[_Token] = []
        while True:
            try:
                token = self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            if not token.expired() and len(kept) < POOL_MAX:
                kept.append(token)
        for token in kept:
            self._put(token)
            self._solved_total -= 1   # 回池不是新解出来的，别把统计灌水

    def stats(self) -> dict:
        """池状态（诊断「首 token 为什么慢」先看它：池空 → 每个请求同步现解）。"""
        return {
            "pool_size": self._pool_size,
            "pool_min": POOL_MIN,
            "pool_max": POOL_MAX,
            "solved_total": self._solved_total,
            "solve_failures": self._solve_failures,
            "refill_inflight": self._batch_inflight,
            "concurrency": settings.CAPTCHA_SOLVE_CONCURRENCY,
            "last_error": self._last_error,
        }

    async def get_verify_param(self, port: int | None = None) -> tuple[str, str | None]:
        """取一枚可用 token：优先池内现成的（亚毫秒），池空才同步补一批。

        返回 (verify_param, region)。region 可为 None（旧求解器无 region 概念）。
        """
        # 1) 池内直取
        token = self._take_ready()
        if token is not None:
            return token.param, token.region

        # 2) 池空/全过期：起一批并发补货，然后等**第一枚**落池 —— 而不是每个请求
        #    各起一个 Node 进程（进程风暴，池越空越雪崩），也不是干等整批补完
        #    （那会把延迟从 ~10s 放大到批次总时长）。批次内部的并发度由信号量限制。
        if not self._batch_inflight:
            logs.warn("captcha", f"池空（{self._pool_size}）：起一批补货，同批请求共享结果")
            self._batch_inflight = True      # 同步置位：同批请求不会再各起一批
            self._spawn_refill(settings.CAPTCHA_SOLVE_CONCURRENCY)

        deadline = time.monotonic() + settings.CAPTCHA_COLD_WAIT
        while time.monotonic() < deadline:
            token = self._take_ready()
            if token is not None:
                return token.param, token.region
            if not self._batch_inflight and self._pool_size == 0:
                break            # 批次已跑完仍无货 → 是真失败，不等满超时
            await asyncio.sleep(0.15)
        self._solve_failures += 1
        raise CaptchaSolveError(f"验证码求解失败: {self._last_error or '多次重试无结果'}")

    def _spawn_refill(self, count: int) -> None:
        """后台起一批补货（fire-and-forget；强引用防 GC）。"""
        task = asyncio.create_task(self._refill_batch(count))
        self._bg_tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            self._bg_tasks.discard(t)
            # 任务被取消/启动前就死掉时，_refill_batch 的 finally 不会跑，这里兜底
            self._batch_inflight = False

        task.add_done_callback(_done)

    # ── 求解 ─────────────────────────────────────────────────────────────────
    async def _solve_one(self, config: dict) -> _Token | None:
        scene = config.get("sceneId") or constants.CAPTCHA_DEFAULTS["sceneId"]
        region = config.get("region") or constants.CAPTCHA_DEFAULTS["region"]
        prefix = config.get("prefix") or constants.CAPTCHA_DEFAULTS["prefix"]

        last_err: str | None = None
        for attempt in range(1, settings.CAPTCHA_SOLVE_RETRIES + 1):
            try:
                param = await self._run_solver(scene, region, prefix)
            except Exception as err:  # noqa: BLE001
                last_err = str(err)
                param = None
            if param:
                if attempt > 1:
                    logs.ok("captcha", f"求解成功（第 {attempt} 次尝试）")
                return _Token(param, region)
            self._last_error = last_err
            logs.warn("captcha", f"第 {attempt}/{settings.CAPTCHA_SOLVE_RETRIES} 次求解未果，重试…")

        logs.warn("captcha", f"求解失败: {last_err or '多次重试无结果'}")
        return None

    async def _run_solver(self, scene: str, region: str, prefix: str) -> str | None:
        solver = settings.CAPTCHA_SOLVER_JS
        if not solver.exists():
            raise RuntimeError(
                f"未找到求解器 {solver}，请先在 captcha_node 下执行 npm install"
            )
        proc = await asyncio.create_subprocess_exec(
            settings.NODE_PATH, str(solver), scene, region, prefix,
            cwd=str(settings.CAPTCHA_SOLVER_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=settings.CAPTCHA_SOLVE_TIMEOUT)
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return None
        except FileNotFoundError as err:
            raise RuntimeError(f"无法启动 Node（{settings.NODE_PATH}）: {err}") from err

        param = None
        for line in stdout.decode("utf-8", "ignore").splitlines():
            if line.startswith("VERIFY_PARAM="):
                param = line[len("VERIFY_PARAM="):].strip()
        return param

    # ── 失效 ─────────────────────────────────────────────────────────────────
    def invalidate(self) -> None:
        """上游返回验证码挑战时清空整池（该批 token/指纹已不可信）。"""
        drained = 0
        while True:
            try:
                self._pool.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._pool_size = max(0, self._pool_size - 1)
            drained += 1
        if drained:
            logs.warn("captcha", f"验证码失效，清空池 {drained} 枚")


captcha_manager = CaptchaManager()
