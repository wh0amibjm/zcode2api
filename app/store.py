"""账号与设置的持久化存储（SQLite）。

数据保存在项目本目录下的 data/accounts.db，采用 WAL 模式，
与 grok2api 的本地 (local) 账号后端保持一致。

运行期账号对象常驻内存（保证轮询游标与状态实时性）；状态类变更同步落库，
请求计数类变更走脏标记延刷（touch_account，5s 合并）；进程启动时从 SQLite 读取快照。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import closing

from . import settings
from .models import PROVIDERS, Account, Status

_TBL = "accounts"
_META = "meta"


class Store:
    """线程安全的账号 / 设置存储，含轮询游标。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._accounts: dict[str, list[Account]] = {p: [] for p in PROVIDERS}
        self._settings: dict = {}
        self._rotation: dict[str, int] = {p: 0 for p in PROVIDERS}
        # 外部改动检测用的常驻连接（见 sync_from_disk）：PRAGMA data_version 只在**其他连接**
        # 改动过库时才变，所以它天然区分"自己写的"和"外面写的"，也不受 WAL / mtime 精度影响
        # —— 这两种信号都试过：WAL 下写入先进 -wal、主库 mtime 未必变；纳秒 mtime 在连续快速
        # 改动时也会撞上。data_version 是 SQLite 为此提供的机制。
        self._watch: sqlite3.Connection | None = None
        self._db_mtime: int = 0
        # 热路径落库的脏标记与合并刷写定时器（见 touch_account）
        self._dirty: set[str] = set()
        self._flush_timer: threading.Timer | None = None
        self._init_db()
        # 常驻 watch 连接在这里就建好 —— `_init_db()` 已确保目录存在。惰性建的话，
        # 两个并发读者可能同时走到"发现是 None"那一步，各自建一条连接，其中一条被
        # 赋值覆盖后永不 close()，泄漏一个 SQLite 句柄。
        self._watch = self._connect()
        self._load()
        self._stamp()

    # ── SQLite 基础 ──────────────────────────────────────────────────────────
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(settings.DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS {_META} (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS {_TBL} (
                    id          TEXT PRIMARY KEY,
                    provider    TEXT NOT NULL,
                    name        TEXT,
                    mode        TEXT,
                    status      TEXT,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    created_at  REAL,
                    data        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_acc_provider ON {_TBL} (provider);
                CREATE INDEX IF NOT EXISTS idx_acc_status   ON {_TBL} (status);
                """
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {_META} (key, value) VALUES ('admin_key', ?)",
                (settings.DEFAULT_ADMIN_KEY,),
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {_META} (key, value) VALUES ('gateway_key', '')"
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {_META} (key, value) VALUES ('quota_refresh_interval', ?)",
                (str(settings.QUOTA_REFRESH_INTERVAL),),
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {_META} (key, value) VALUES ('account_concurrency', ?)",
                (str(settings.ACCOUNT_CONCURRENCY),),
            )
            conn.commit()

    def _load(self) -> None:
        with closing(self._connect()) as conn:
            meta_rows = conn.execute(f"SELECT key, value FROM {_META}").fetchall()
            self._settings = {r["key"]: r["value"] for r in meta_rows}
            self._settings.setdefault("admin_key", settings.DEFAULT_ADMIN_KEY)
            self._settings.setdefault("gateway_key", "")
            self._settings.setdefault("quota_refresh_interval", str(settings.QUOTA_REFRESH_INTERVAL))
            self._settings.setdefault("account_concurrency", str(settings.ACCOUNT_CONCURRENCY))

            # 就地刷新，**不整体替换** Account 对象：`_dispatch`/`_try_account` 在做请求时
            # 持有 Account 引用，替换会让它们在结束时用旧快照 INSERT OR REPLACE 写回，
            # 把外部刚写入的状态（enabled/jwt）与本进程期间累积的 use_count/fail_count/
            # risk_strikes/额度刷新一起回退。热同步（sync_from_disk）被设计成"外部写库后
            # 无需重启"，而扩容正是每隔几分钟就写一次库 —— 不做这一步，外部写得越勤、
            # 回退窗口越多。
            existing = {a.id: a for accounts in self._accounts.values() for a in accounts}
            rebuilt: dict[str, list[Account]] = {p: [] for p in PROVIDERS}
            rows = conn.execute(
                f"SELECT data FROM {_TBL} ORDER BY created_at ASC"
            ).fetchall()
            for row in rows:
                try:
                    data = json.loads(row["data"])
                except json.JSONDecodeError:
                    continue
                if not isinstance(data, dict):
                    continue
                account = existing.get(data.get("id"))
                if account is None:
                    try:
                        account = Account.from_dict(data)
                    except TypeError:
                        continue
                else:
                    for key, value in data.items():
                        if key not in Account.__dataclass_fields__:
                            continue
                        if key == "recent_results":
                            # 这个字段不落库（record_result 只改内存），磁盘上那份是旧的：
                            # 直接用磁盘值会把本进程刚记录的请求明细抹掉。取更完整的一份。
                            if len(value or []) > len(account.recent_results or []):
                                account.recent_results = value
                            continue
                        setattr(account, key, value)
                if account.provider in rebuilt:
                    rebuilt[account.provider].append(account)
            self._accounts = rebuilt

    def _db_signature(self) -> int:
        """外部改动指纹：常驻连接上的 `PRAGMA data_version`。

        只读，不会触发同步；其他连接每次提交后它会 +1。自己写的改动不会让它变，所以不需要
        "写后盖戳" 那套（早先的实现靠 mtime，先在 WAL 上漏检、后又在纳秒精度上撞车）。

        连接在 `__init__` 里就建好了（见那里的注释），此处不再惰性建。
        """
        try:
            row = self._watch.execute("PRAGMA data_version").fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error:
            return 0

    def _stamp(self) -> None:
        """记住库当前指纹。

        用 data_version 之后其实不必在写后调用（它本就不因自己的写而变），保留是为了让
        `_load()` 之后有个统一的"对齐基线"动作，语义上更清楚。
        """
        self._db_mtime = self._db_signature()

    def sync_from_disk(self) -> bool:
        """库被**外部进程**改过就重载，返回是否真的重载了。

        为什么需要：`cli.py login`、导出/导入脚本、后台工具都是**直接写这个库**的，而 store 是
        内存缓存 —— 原先只在进程启动时 `_load()` 一次，于是新账号必须重启网关才可见
        （实测：CLI 打印"已保存账号"，管理接口却仍只列旧账号）。读入口惰性检查 mtime 即可
        根治：不需要 CLI 配合改造，也不需要额外轮询线程。

        顺带一起刷新的还有 `_settings` —— 所以后台改 gateway_key / admin_key 之类同样不必重启。
        """
        sig = self._db_signature()
        if not sig or sig == self._db_mtime:
            return False
        with self._lock:
            # 双检：等锁期间可能已被别的线程同步过
            sig = self._db_signature()
            if not sig or sig == self._db_mtime:
                return False
            self._load()
            self._db_mtime = sig
        return True

    def _persist_account(self, account: Account) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                f"""INSERT OR REPLACE INTO {_TBL}
                    (id, provider, name, mode, status, enabled, created_at, data)
                    VALUES (?,?,?,?,?,?,?,?)""",
                (
                    account.id, account.provider, account.name, account.mode,
                    account.status, 1 if account.enabled else 0, account.created_at,
                    json.dumps(account.to_dict(), ensure_ascii=False),
                ),
            )
            conn.commit()
        self._stamp()   # 同上：不盖戳的话，写后紧接的读会误判成外部改动、白重载整个库

    def _delete_account(self, account_id: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(f"DELETE FROM {_TBL} WHERE id = ?", (account_id,))
            conn.commit()
        self._stamp()   # 自己写的改动要盖戳，否则下次读会被误判成外部改动而白重载

    def _set_meta(self, key: str, value: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO {_META} (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

        self._stamp()
    def save(self) -> None:
        """全量落库（兜底接口）。"""
        with self._lock:
            for accounts in self._accounts.values():
                for account in accounts:
                    self._persist_account(account)

    # ── 设置 ─────────────────────────────────────────────────────────────────
    def get_setting(self, key: str, default=None):
        with self._lock:
            return self._settings.get(key, default)

    def set_setting(self, key: str, value) -> None:
        with self._lock:
            self._settings[key] = str(value)
            self._set_meta(key, str(value))

    def admin_key(self) -> str:
        return str(self.get_setting("admin_key", settings.DEFAULT_ADMIN_KEY) or "")

    def gateway_key(self) -> str:
        return str(self.get_setting("gateway_key", "") or "")

    def quota_refresh_interval(self) -> int:
        try:
            return max(0, int(self.get_setting("quota_refresh_interval", settings.QUOTA_REFRESH_INTERVAL)))
        except (TypeError, ValueError):
            return settings.QUOTA_REFRESH_INTERVAL

    def account_concurrency(self) -> int:
        """单账号并发上限（0 = 不限）。运行时可改（meta 表），改后即生效。"""
        try:
            return max(0, int(self.get_setting("account_concurrency", settings.ACCOUNT_CONCURRENCY)))
        except (TypeError, ValueError):
            return settings.ACCOUNT_CONCURRENCY

    # ── 账号读取 ─────────────────────────────────────────────────────────────
    def list_accounts(self, provider: str | None = None) -> list[Account]:
        self.sync_from_disk()
        with self._lock:
            if provider:
                return list(self._accounts.get(provider, []))
            return [a for p in PROVIDERS for a in self._accounts[p]]

    def find(self, provider: str, id_or_name: str) -> Account | None:
        self.sync_from_disk()
        with self._lock:
            return self._find_locked(provider, id_or_name)

    def find_any(self, id_or_name: str) -> Account | None:
        self.sync_from_disk()
        with self._lock:
            for p in PROVIDERS:
                for a in self._accounts[p]:
                    if a.id == id_or_name:
                        return a
        return None

    def _find_locked(self, provider: str, id_or_name: str) -> Account | None:
        for a in self._accounts.get(provider, []):
            if a.id == id_or_name or a.name == id_or_name:
                return a
        return None

    # ── 账号增删改 ───────────────────────────────────────────────────────────
    def add_account(self, provider: str, name: str, secret: str) -> Account:
        if provider not in PROVIDERS:
            raise ValueError(f"不支持的 provider: {provider}")
        account = Account.create(provider, name, secret)
        with self._lock:
            for a in self._accounts[provider]:
                if a.secret and a.secret == account.secret:
                    return a  # 跳过重复 token
            self._assign_fingerprint(account)  # 入池即分配独立设备指纹
            account.install_id = str(uuid.uuid4())  # 安装身份：稳定安装令牌
            self._accounts[provider].append(account)
            self._persist_account(account)
        return account

    @staticmethod
    def _assign_fingerprint(account: Account) -> None:
        """给账号分配客户端指纹并固化为 dict（随 asdict 落库，取用时还原）。"""
        from .fingerprint import profile_for

        profile = profile_for(account)
        account.fingerprint = {
            "platform": profile.platform, "arch": profile.arch,
            "os_version": profile.os_version, "language": profile.language,
            "timezone": profile.timezone, "screen": profile.screen,
            "device_mid": profile.device_mid,
        }

    def remove_account(self, provider: str, id_or_name: str) -> bool:
        with self._lock:
            items = self._accounts.get(provider, [])
            target = next((a for a in items if a.id == id_or_name or a.name == id_or_name), None)
            if not target:
                return False
            self._accounts[provider] = [a for a in items if a.id != target.id]
            self._delete_account(target.id)
            return True

    def update_account(self, account: Account) -> bool:
        """持久化某个账号的当前状态。

        账号已从内存池删除时拒绝写回，避免后台任务 INSERT OR REPLACE 把已删行救活。
        """
        with self._lock:
            if self._find_locked(account.provider, account.id) is None:
                return False
            self._persist_account(account)
            return True

    def set_enabled(self, provider: str, id_or_name: str, enabled: bool) -> bool:
        with self._lock:
            account = self._find_locked(provider, id_or_name)
            if not account:
                return False
            account.enabled = enabled
            if not enabled:
                account.status = Status.DISABLED
            elif account.status == Status.DISABLED:
                account.status = Status.ACTIVE
            self._persist_account(account)
            return True

    def reset_risk_ban(self, provider: str, id_or_name: str) -> bool:
        """解除风控封禁（人工复核后）：清 risk_strikes / last_error，复位 ACTIVE。

        只认**风控封禁**形态（enabled=True 且 status=DISABLED）——那是 ban_for_risk
        的签名，后台手动停用的账号（enabled=False）不在此列，绝不被这个动作顺手打开。
        """
        with self._lock:
            account = self._find_locked(provider, id_or_name)
            if not account:
                return False
            if not account.enabled or account.status != Status.DISABLED:
                return False
            account.status = Status.ACTIVE
            account.risk_strikes = 0
            account.last_error = None
            account.cooling_until = None
            account.exhausted_until = None
            self._persist_account(account)
            return True

    # ── 热路径落库（脏标记 + 合并刷写）────────────────────────────────────────
    # 成功路径曾对每个请求同步 update_account：全局 RLock + 新建 SQLite 连接 +
    # 全量 JSON 序列化 + commit，全在事件循环线程上 —— 并发下所有请求的收尾在
    # 这一点串行，还顺带卡住其他协程。计数类字段（use_count/last_used_at/
    # recent_results/risk_strikes 清零）改为内存即时生效、5s 合并落库；进程退出
    # 前未刷的最多丢 5s 计数，可接受。状态类变更（冷却/封禁/额度/启停）仍走
    # update_account / _mark 即时落 —— 那些决定账号能不能被 select，等不得。
    # 延迟为 0 时不起刷写线程（测试专用：落库时机完全由 flush_dirty 显式控制）。
    _FLUSH_DELAY_SECONDS = 5.0

    def touch_account(self, account: Account) -> None:
        """热路径计数变更登记：内存对象已被调用方改过，这里只安排落库。"""
        with self._lock:
            if self._find_locked(account.provider, account.id) is None:
                return
            self._dirty.add(account.id)
            self._schedule_flush_locked()

    def _schedule_flush_locked(self) -> None:
        """安排一次延后刷写（须持锁调用）。延迟为 0 = 手动模式，不起线程。"""
        if self._FLUSH_DELAY_SECONDS > 0 and self._flush_timer is None:
            timer = threading.Timer(self._FLUSH_DELAY_SECONDS, self._flush_tick)
            timer.daemon = True
            self._flush_timer = timer
            timer.start()

    def _flush_tick(self) -> None:
        with self._lock:
            self._flush_timer = None
        self.flush_dirty()

    def flush_dirty(self) -> None:
        """把脏账号落库。单条失败把 id 放回待刷并重排定时器，下次再试。

        逐条**持锁**复检再写：targets 收集与写回之间账号可能被 remove_account
        删掉，INSERT OR REPLACE 不复检就会把已删行救活，而 flush 自己的 commit
        会让 _watch.data_version 变化、下次 sync_from_disk 把复活行重新载入
        （review P1）。flush 在 timer 线程，持锁只让 loop 上的 touch_account
        偶发等一条 persist（ms 级），仍远好于旧的每请求同步落库。
        """
        with self._lock:
            dirty = self._dirty
            self._dirty = set()
            targets = [a for accounts in self._accounts.values() for a in accounts
                       if a.id in dirty]
        missed: set[str] = set()
        for account in targets:
            with self._lock:
                if self._find_locked(account.provider, account.id) is None:
                    continue
                try:
                    self._persist_account(account)
                except Exception:  # noqa: BLE001 - 单条失败不拖垮整批（timer 线程内不可抛）
                    missed.add(account.id)
        if missed:
            with self._lock:
                self._dirty |= missed
                self._schedule_flush_locked()

    # ── 轮询选择 ─────────────────────────────────────────────────────────────
    def select(self, provider: str, skip_ids: set[str] | None = None) -> Account | None:
        """按 round-robin 选择下一个可用账号。用完 / 失效的自动跳过。"""
        self.sync_from_disk()
        skip_ids = skip_ids or set()
        now = time.time()
        with self._lock:
            pool = [
                a for a in self._accounts.get(provider, [])
                if a.is_selectable(now) and a.id not in skip_ids
            ]
            if not pool:
                return None
            idx = self._rotation.get(provider, 0) % len(pool)
            account = pool[idx]
            self._rotation[provider] = (idx + 1) % len(pool)
            return account

    # ── 导入 / 导出 ─────────────────────────────────────────────────────────
    def export(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "exported_at": time.time(),
                "providers": {
                    p: [
                        {"name": a.name, "mode": a.mode, "secret": a.secret}
                        for a in self._accounts[p]
                    ]
                    for p in PROVIDERS
                },
            }

    def import_accounts(self, payload: dict) -> int:
        providers = payload.get("providers", {})
        count = 0
        for provider, items in providers.items():
            if provider not in PROVIDERS or not isinstance(items, list):
                continue
            for it in items:
                secret = it.get("secret") or it.get("token") or it.get("jwtToken") or it.get("apiKey")
                if not secret:
                    continue
                self.add_account(provider, it.get("name", provider), secret)
                count += 1
        return count


# 单例
store = Store()
