"""运行期配置：环境变量 + 默认值。

所有可调参数集中在此。账号与凭证不在此处，而是持久化到 data/ 目录（见 store.py）。
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

from . import constants

load_dotenv()

# 项目根目录
ROOT_DIR = Path(__file__).resolve().parents[1]


def _resolve_path(env_name: str, default: str) -> Path:
    raw = (os.getenv(env_name, default) or default).strip()
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT_DIR / path
    return path


def _int(env_name: str, default: int) -> int:
    try:
        return int(os.getenv(env_name, str(default)))
    except (TypeError, ValueError):
        return default


# ── 目录 ─────────────────────────────────────────────────────────────────────
DATA_DIR = _resolve_path("ZCODE_DATA_DIR", "data")
# 账号与设置持久化到本地 SQLite（与 grok2api 的 local 后端一致）
DB_PATH = DATA_DIR / "accounts.db"
# 前端目录（前后端分离）：默认仓库根 frontend/，可用 ZCODE_FRONTEND_DIR 指向
# 独立部署目录（线上 /data/zcode-hub/frontend）；包内 statics 仅作兜底
FRONTEND_DIR = _resolve_path(
    "ZCODE_FRONTEND_DIR",
    "frontend" if (ROOT_DIR / "frontend").is_dir() else str(Path(__file__).resolve().parent / "statics"),
)

# ── 服务 ─────────────────────────────────────────────────────────────────────
PORT = _int("ZCODE_PORT", 3000)
HOST = os.getenv("ZCODE_HOST", "0.0.0.0")

# ── 鉴权 ─────────────────────────────────────────────────────────────────────
# 后台管理密码默认值，首次启动写入 data/accounts.db，之后以数据库（meta 表）为准。
DEFAULT_ADMIN_KEY = os.getenv("ZCODE_ADMIN_KEY", "zcode")

# ── 验证码 ───────────────────────────────────────────────────────────────────
# 预解 token 池（对齐 zapi captcha.ts：热路径从池直取，后台循环补库存）
CAPTCHA_POOL_MIN = _int("CAPTCHA_POOL_MIN", 3)        # 目标库存（低于则补）
CAPTCHA_POOL_MAX = _int("CAPTCHA_POOL_MAX", 10)       # 池上限
CAPTCHA_TOKEN_TTL = _int("CAPTCHA_TOKEN_TTL", 95_000) # 单枚 token 最大可用时长（ms；上游实际 ~2min）
CAPTCHA_CONFIG_CACHE_TTL = _int("CAPTCHA_CONFIG_CACHE_TTL", 600_000)  # ms

# ── 活动自动领取 ─────────────────────────────────────────────────────────────
# 活动是分批投放的（同一账号的 preview 会先后出现不同场次），入池时领一次会漏。
# 周期检查并自动领取；billing/* 是上游 WAF 风险点，故节拍拉长 + 账号间错峰。
#
# 默认 6 小时（2026-09-26 上调，原 1800s）：那天 30 分钟一轮的 billing 与注册链路共用
# 同一批出口 IP，高频查询把出口打到被上游丢包封锁（z.ai 全域名超时、其它站点正常）。
# 活动以「天」计，6 小时一轮足够吃到新场次，又把流量压到 1/12。
CLAIM_INTERVAL = _int("ZCODE_CLAIM_INTERVAL", 6 * 3600)  # 0 = 关闭周期领取
CLAIM_STAGGER = _int("ZCODE_CLAIM_STAGGER", 5)           # 账号之间的间隔秒数
CLAIM_START_DELAY = _int("ZCODE_CLAIM_START_DELAY", 60)  # 启动后首次检查的延迟
# 领取遇瞬时异常（验证码预解池的 pe VM 偶发 stall）后的重试等待
CLAIM_RETRY_WAIT = _int("ZCODE_CLAIM_RETRY_WAIT", 5)
# 入池后到第一次领取之间的"等站点落定"延迟。OAuth 刚拿到 JWT 时，站点侧（billing）可能还没把
# 这个账号同步过来，此刻打过去必然领不到 —— 2026-09-26 观察：同一批号里有的领到、有的报失败，
# 差别就是这几秒。与其撞了再重试，不如先等它落定。
CLAIM_SETTLE_SECONDS = _int("ZCODE_CLAIM_SETTLE_SECONDS", 30)

# ── 额度耗尽试探窗 ───────────────────────────────────────────────────────────
# 上游 free Start Plan 是日窗口，额度耗尽时 billing 会回落成空数组（失去「数字
# 恢复」这条路径）。EXHAUSTED 账号到期后放回池子试一次，成功即自动复活。
EXHAUST_RETRY_SECONDS = _int("ZCODE_EXHAUST_RETRY_SECONDS", 1800)

# 验证码求解（无浏览器：Node + jsdom 模拟浏览器环境，运行阿里云无痕 SDK）
NODE_PATH = os.getenv("ZCODE_NODE_PATH", "node")
CAPTCHA_SOLVER_DIR = ROOT_DIR / "captcha_node"
CAPTCHA_SOLVER_JS = CAPTCHA_SOLVER_DIR / "solver.js"
CAPTCHA_SOLVE_RETRIES = _int("ZCODE_CAPTCHA_RETRIES", 4)
CAPTCHA_SOLVE_TIMEOUT = _int("ZCODE_CAPTCHA_TIMEOUT", 40)  # 每次求解超时（秒）

# ── 用量监控 ─────────────────────────────────────────────────────────────────
# 后台自动刷新账号额度的间隔（秒）。0 表示关闭后台轮询，仅按需刷新。
QUOTA_REFRESH_INTERVAL = _int("ZCODE_QUOTA_REFRESH_INTERVAL", 60)
# 成功对话后计费刷新的最小间隔（秒）：billing/* 连续查询易触发上游拦截，
# 每条消息都刷是流量放大器，与 monitor 轮询共享 last_checked_at 去抖。
BILLING_REFRESH_MIN_INTERVAL = _int("ZCODE_BILLING_REFRESH_MIN_INTERVAL", 60)
# ── 上游错误重试 / 冷却（参数可设定）─────────────────────────────────────────
# 429 频控：账号不冷却，原地等待后重试，耗尽后换下一个账号（账号保持可用）
RETRY_429_TIMES = _int("ZCODE_RETRY_429_TIMES", 5)       # 429 重试次数
RETRY_429_WAIT = _int("ZCODE_RETRY_429_WAIT", 60)        # 429 重试等待秒数（上游 Retry-After 优先）
RETRY_429_WAIT_MAX = _int("ZCODE_RETRY_429_WAIT_MAX", 120)  # Retry-After 采信上限（防吊死客户端）
# 5xx 等一般错误：重试，耗尽后账号冷却 COOLING_SECONDS 并换下一个账号
RETRY_5XX_TIMES = _int("ZCODE_RETRY_5XX_TIMES", 3)       # 5xx 重试次数
RETRY_5XX_WAIT = _int("ZCODE_RETRY_5XX_WAIT", 5)         # 5xx 重试等待秒数
# 限流（cooling）冷却时长（秒）——仅 5xx 重试耗尽 / 连接失败使用
COOLING_SECONDS = _int("ZCODE_COOLING_SECONDS", 300)
# 单账号并发上限（0 = 不限）。默认 2；运行期可在后台设置改（meta 表即时生效）
ACCOUNT_CONCURRENCY = _int("ZCODE_ACCOUNT_CONCURRENCY", 2)

# ── 上游端点 ─────────────────────────────────────────────────────────────────
# 上游端点：默认值统一收口在 constants.py，环境变量仅作覆盖
UPSTREAM = {
    "zai": os.getenv("ZAI_UPSTREAM_URL", constants.MESSAGES_URLS["zai"]),
    "zai_fallback": os.getenv("ZAI_FALLBACK_URL", constants.MESSAGES_URLS["zai_fallback"]),
    "bigmodel": os.getenv("BIGMODEL_UPSTREAM_URL", constants.MESSAGES_URLS["bigmodel"]),
}

# ZCode 计费 / 额度查询端点
ZCODE_BILLING_BASE = constants.BILLING_BASE
# 激活事件上报（测试时指向 Mock 上游）
ZCODE_EVENT_REPORT_URL = os.getenv("ZCODE_EVENT_REPORT_URL", constants.EVENT_REPORT_URL)

# OAuth 与兑换链 origin（测试时指向 Mock 上游）
OAUTH_API_BASE = os.getenv("ZCODE_OAUTH_API_BASE", constants.ZCODE_ORIGIN + "/api/v1")
ZAI_EXCHANGE_ORIGIN = os.getenv("ZCODE_EXCHANGE_ORIGIN", constants.ZAI_API_ORIGIN)

# 上游 UA：显式 env 覆盖优先；否则跟随 constants 的动态版本
# （写成常量会在 import 时被求值一次，探测到新版本也刷不进去）
USER_AGENT_OVERRIDE = os.getenv("UPSTREAM_USER_AGENT", "")


def user_agent() -> str:
    return USER_AGENT_OVERRIDE or constants.USER_AGENT
APP_VERSION = "2.5.11"

_FRONTEND_VERSION_FILE = FRONTEND_DIR / "version"


def frontend_version() -> str:
    """前端版本号（frontend/version 文件，每次读取 → 前端独立发版即生效）。

    文件缺失/为空时回退 APP_VERSION，保证本地开发与旧部署不破。
    """
    try:
        v = _FRONTEND_VERSION_FILE.read_text("utf-8").strip()
        return v or APP_VERSION
    except OSError:
        return APP_VERSION
