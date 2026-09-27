"""核心网关：/v1/messages（Anthropic 风格）与 /v1/chat/completions（OpenAI 风格）。

共用多账号轮询 + 额度用完自动换号 + 阿里无痕验证自动续期；OpenAI 端点由
openai_compat 做双向格式转换，调度与错误处理策略完全一致。
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .. import constants, logs, reqlog, settings
from ..agent import build_request
from ..auth_admin import verify_gateway_key
from ..captcha import captcha_manager
from ..models import Account, Status
from ..openai_compat import StreamConverter, anthropic_to_openai, openai_to_anthropic
from ..quota import fetch_quota
from ..store import store
from ..upstream_http import SSL_CTX

_sleep = asyncio.sleep  # 模块级引用：测试可 patch 此名而免污染全局 asyncio

router = APIRouter()

# ── 上游 HTTP 客户端 ─────────────────────────────────────────────────────────
# 此前**每个请求**新建 httpx.AsyncClient（`_try_account` 内），代价是每请求一次
# TCP+TLS 握手、连接池现建现扔；流式长回复下这条连接本身还能活数分钟，白建白扔
# 尤其浪费。复用的另一半理由在指纹层：官方客户端本来就保持长连接，每请求新建
# 反而是异常特征。
#
# 连接池按 (scheme, host, port) 复用，**账号身份在 header 层**（build_request 逐请求
# 构造 jwt/api-key/指纹头），所以不会串味；一条 HTTP/1.1 连接同一时刻也只服务一个
# 请求。若上游确实按连接归类（未实测），用 ZCODE_HTTP_REUSE=0 退回每请求新建。
_HTTP_REUSE = settings.HTTP_REUSE

_UPSTREAM_TIMEOUT = httpx.Timeout(connect=30.0, read=None, write=120.0, pool=30.0)
_UPSTREAM_LIMITS = httpx.Limits(max_connections=200, max_keepalive_connections=64)
_upstream_client: httpx.AsyncClient | None = None
_upstream_client_loop: asyncio.AbstractEventLoop | None = None


def _client() -> httpx.AsyncClient:
    """上游客户端。

    默认返回**共享单例**：连接复用，且绑定事件循环 —— httpx 把连接池挂在创建时的
    loop 上，跨 loop 复用会直接报错，所以 loop 变了就重建（生产只有一个 loop，这个
    分支永不触发；测试每条用例一个新 loop，正是靠它拿到干净实例）。

    `ZCODE_HTTP_REUSE=0` 时返回**每请求一个独立实例**。这个分支必须在这里分叉：
    `_release_client` 在回退模式下会 `aclose()` 掉传进去的客户端，若它拿到的是共享
    单例，就会在别的并发请求正读流时把客户端关掉。
    """
    global _upstream_client, _upstream_client_loop
    if not _HTTP_REUSE:
        return httpx.AsyncClient(timeout=_UPSTREAM_TIMEOUT, limits=_UPSTREAM_LIMITS, verify=SSL_CTX)
    try:
        loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if (_upstream_client is None or _upstream_client.is_closed
            or _upstream_client_loop is not loop):
        _upstream_client = httpx.AsyncClient(timeout=_UPSTREAM_TIMEOUT, limits=_UPSTREAM_LIMITS, verify=SSL_CTX)
        _upstream_client_loop = loop
    return _upstream_client


async def _release_client(client: httpx.AsyncClient) -> None:
    """关客户端 —— 只关"每请求新建"的回退路径；共享单例留给 lifespan 收口。"""
    if not _HTTP_REUSE:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 - 关闭失败不该掩盖真实错误
            pass


async def aclose_client() -> None:
    """进程退出时收口共享客户端（main.lifespan 调用）。"""
    global _upstream_client, _upstream_client_loop
    client, _upstream_client = _upstream_client, None
    _upstream_client_loop = None
    if client is not None and not client.is_closed:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass

MAX_CAPTCHA_RETRIES = 3
MAX_ACCOUNT_ATTEMPTS = 5

# 常量收口：模型表与被拒信号关键字统一在 app/constants.py
MODEL_NAME_MAP = constants.MODEL_NAME_MAP
AVAILABLE_MODELS = constants.AVAILABLE_MODELS
_EXHAUST_KEYWORDS = constants.EXHAUST_KEYWORDS


def _detect_provider(body: dict, headers) -> str:
    model = body.get("model") or ""
    if model.startswith("bigmodel/") or headers.get("x-provider") == "bigmodel":
        return "bigmodel"
    return "zai"


def _normalize_body(body: dict) -> dict:
    model = body.get("model")
    if isinstance(model, str) and "/" in model:
        model = "/".join(model.split("/")[1:])
    if isinstance(model, str):
        model = MODEL_NAME_MAP.get(model.lower(), model)
        body["model"] = model

    # 上游对 max_tokens 有硬校验（400 code 1210），钳制到合法区间并记录钳制动作
    raw = body.get("max_tokens")
    if raw is not None and not isinstance(raw, bool):
        try:
            mt = int(float(raw))
        except (TypeError, ValueError):
            mt = None
        if mt is not None:
            clamped = max(1, min(mt, constants.MAX_TOKENS_LIMIT))
            if clamped != mt:
                logs.warn("gateway", f"max_tokens {mt} 超出上游范围 [1,{constants.MAX_TOKENS_LIMIT}]，钳制为 {clamped}")
            body["max_tokens"] = clamped

    messages = body.get("messages")
    if isinstance(messages, list):
        bridged = []
        for msg in messages:
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                bridged.append({**msg, "content": [{"type": "text", "text": msg["content"]}]})
            else:
                bridged.append(msg)
        body["messages"] = bridged
    return body


def _is_captcha_error(text: str) -> bool:
    low = text.lower()
    return "captcha" in low or "verify token" in low or "verify failed" in low


def _detect_captcha_challenge(resp: httpx.Response, text: str | None = None) -> str | None:
    """验证码挑战双检测（对齐 zapi handler.ts）。

    三种形态：
      1. 响应头 x-aliyun-captcha-verify-param 存在（官方挑战信号）
      2. HTTP 400/403 + body {"code":3007}（2026-08 观测的 body 内挑战）
      3. HTTP 403 + 文案 captcha/verify（老检测，保留兼容）
    返回挑战标记（非 None 即挑战），否则 None。
    """
    # 1) challenge 响应头
    header_val = resp.headers.get(constants.CAPTCHA_HEADER)
    if header_val and header_val.strip():
        return "header"

    if text is None:
        return None
    low = text.lower()

    # 2) body code 3007（400/403 任意状态）
    if resp.status_code in (400, 403) and any(m in text for m in constants.CAPTCHA_BODY_MARKERS):
        return "in-body-3007"

    # 3) 403 + 挑战文案
    if resp.status_code == 403 and _is_captcha_error(low):
        return "text"

    return None


def _is_exhausted(status_code: int, text: str) -> bool:
    # 429 是频控信号，优先于一切 body 关键词：429 body 带额度文案时
    # （api.z.ai 实测形态）必须走频控重试，不得判成额度耗尽踢号。
    if status_code == 429:
        return False
    if status_code in constants.EXHAUST_HTTP_STATUSES:
        return True
    low = text.lower()
    return any(k in low for k in _EXHAUST_KEYWORDS)


def _is_risk_control(status_code: int, text: str) -> bool:
    """风控信号判定（3012「unusual activity」/ messages 端点 405）。

    与验证码挑战互斥：调用点已先排除 challenge 形态。命中即账号级风控，
    需指数退避冷却，而非直接回传客户端错误（会导致下次立刻重打、加剧风控）。
    """
    if status_code in constants.RISK_CONTROL_HTTP_STATUSES:
        return True
    low = text.lower()
    return any(m.lower() in low for m in constants.RISK_CONTROL_MARKERS)


# ── HTTP 200 里的业务错误（线上实测 2026-09-26）───────────────────────────────
# start-plan（JWT）通道额度耗尽时不回 4xx，而是：
#     HTTP/1.1 200 OK · content-type: application/json
#     {"code":1005,"msg":"exceed quota limit","logid":"…"}
# 只按 status_code 判成功的写法会把它当成功：recent_results 记 ok=True、账号不换、
# 客户端收到「200 但内容不是 message」的响应，额度回来那天也没人知道。
# 做法是把它归一化成等效 HTTP 状态码，复用下方既有分支（challenge/风控/额度/
# 5xx），而不是另起一套错误处理 —— 判定口径与真实 4xx 完全同源。
_NORMALIZED_EXHAUST = 402   # 落 EXHAUST_HTTP_STATUSES
_NORMALIZED_RISK = 405      # 落 RISK_CONTROL_HTTP_STATUSES
_NORMALIZED_CAPTCHA = 400   # 走 challenge 分支：清池换码重试（按 body 的 code==3007 判定）
# 未知业务码：按**确定性错误**处理，落下方"其它 4xx"分支（回传客户端、不重试、不冷却）。
# 早先映射成 502 是错的：未知 code 多半是参数/契约类错误，重试与冷却都是无效动作，
# 还会把一个健康账号关进 COOLING_SECONDS 的冷却里。
_NORMALIZED_OTHER = 400


async def _sniff_business_error(resp: httpx.Response) -> tuple[int | None, bytes | None]:
    """非 SSE 的 2xx 响应预读一次，判 body 业务码。

    返回 (归一化状态码或 None, 已消费的响应体或 None)。None 状态码 = 正常响应，
    此时必须把读到的体交回调用方（流已被读走，再迭代只会拿到空）。SSE 不读。
    """
    ctype = (resp.headers.get("content-type") or "").lower()
    if "event-stream" in ctype:
        return None, None                     # 流式成功响应的体归调用方
    raw = await resp.aread()
    text = raw.decode("utf-8", "ignore")
    body = _safe_json(text)
    if not isinstance(body, dict):
        return None, raw                      # 非 JSON 交给下游格式校验（garbage_body 等）
    code = body.get("code")
    if not isinstance(code, int) or code == 0:
        return None, raw                      # 无业务码 = 正常响应

    # 关键词只在 msg/message 字段里找，**不扫全文**：2xx 的响应体天然带 balance /
    # quota / expires_at 这类字段名，按子串扫全文会把成功响应判成额度耗尽 ——
    # 后果是一个健康账号被标 EXHAUSTED、带着试探窗退出轮询，而请求其实成功了。
    low = str(body.get("msg") or body.get("message") or "").lower()

    if code == 1005 or any(k in low for k in _EXHAUST_KEYWORDS):
        return _NORMALIZED_EXHAUST, raw
    if any(m.lower() in low for m in constants.RISK_CONTROL_MARKERS):
        return _NORMALIZED_RISK, raw
    # 验证码挑战按 code 直判，不走 _detect_captcha_challenge：那条 body 分支要求
    # status in (400,403)，而本函数只在 2xx 时被调用，靠它等于这条分支永远不可达。
    # 不可达的代价很具体：200+3007 不清池、不换码，反而落进未知码分支让健康账号
    # 被 5xx 重试后冷却，下一轮继续拿同一批已失效的 token 撞。
    if code == 3007:
        return _NORMALIZED_CAPTCHA, raw
    return _NORMALIZED_OTHER, raw


def _parse_retry_after(value: str | None) -> int | None:
    """解析 Retry-After（仅秒数形态；HTTP-date 形态少见，放弃即用默认重试等待）。

    非正数不采信；超长值封顶采信 —— 尊重上游意图的同时防止把客户端吊死。
    """
    if not value:
        return None
    try:
        secs = int(float(value.strip()))
    except (ValueError, AttributeError):
        return None
    return min(secs, settings.RETRY_429_WAIT_MAX) if secs > 0 else None


def _mark(account: Account, status_value: str, error: str | None = None) -> None:
    account.status = status_value
    account.last_error = error
    if status_value == Status.COOLING:
        account.cooling_until = time.time() + settings.COOLING_SECONDS
    elif status_value == Status.EXHAUSTED:
        # 额度是日窗口：给一个试探窗，到期自动放回池子试一次。「成功即复活」
        # 在成功分支收口，因此额度真回来了账号无需人工干预。
        account.exhausted_until = time.time() + settings.EXHAUST_RETRY_SECONDS
    store.update_account(account)


def _last_user_text(body: dict) -> str:
    for msg in reversed(body.get("messages") or []):
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    return part.get("text", "")
    return ""


def _responses_to_openai(payload: dict) -> dict:
    """OpenAI Responses API 请求 -> OpenAI Chat Completions 请求。

    只做形状转换，不碰账号池：转换完直接走 chat/completions 那条已经验证过的调度链路
    （账号轮询、验证码、429/5xx 容灾都在 _dispatch 里），所以三条协议面共享同一份上游逻辑。
    `instructions` 变 system，`input` 的两种形态（字符串 / item 数组）都收。
    """
    out: dict = {}
    for key in ("model", "temperature", "top_p", "stream", "tools", "tool_choice",
                "parallel_tool_calls", "metadata"):
        if key in payload:
            out[key] = payload[key]
    if payload.get("max_output_tokens") is not None:
        out["max_tokens"] = payload["max_output_tokens"]

    messages: list[dict] = []
    if payload.get("instructions"):
        messages.append({"role": "system", "content": str(payload["instructions"])})

    inp = payload.get("input")
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if content is None:
                content = item.get("text") or ""
            if isinstance(content, list):
                parts: list[dict] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype in ("input_text", "output_text", "text"):
                        parts.append({"type": "text", "text": block.get("text", "")})
                    elif btype in ("input_image", "image_url"):
                        url = block.get("image_url") or (block.get("source") or {}).get("data")
                        if url:
                            parts.append({"type": "image_url", "image_url": {"url": url}})
                content = parts
            messages.append({"role": item.get("role") or "user", "content": content})
    out["messages"] = messages
    return out


def _chat_to_responses(chat: dict, rid: str, mid: str, model: str) -> dict:
    """OpenAI Chat Completions 响应 -> Responses 响应对象。"""
    choice = (chat.get("choices") or [{}])[0] if isinstance(chat.get("choices"), list) else {}
    message = choice.get("message") or {}
    text = message.get("content") or ""
    if isinstance(text, list):  # 上游偶尔回 content 数组
        text = "".join(b.get("text", "") for b in text if isinstance(b, dict))
    usage = chat.get("usage") or {}
    return {
        "id": rid,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": [{
            "id": mid,
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }],
        # OpenAI 在部分 SDK 里直接读 output_text，这里一并给出，避免客户端自己拼装
        "output_text": text,
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        },
    }


@router.get("/v1/models", dependencies=[Depends(verify_gateway_key)])
async def list_models():
    """列出可用模型（Anthropic /v1/models 风格）。"""
    return {
        "object": "list",
        "data": [
            {"id": i, "type": "model", "display_name": i, "created_at": "2025-01-01T00:00:00Z"}
            for i in AVAILABLE_MODELS
        ],
    }


def _estimate_tokens(body: dict) -> int:
    """粗略估算 input tokens（system / messages / tools 都算）。

    Claude Code 只拿这个数判断上下文余量，不要求精确；按 ASCII ~4 字符/token、CJK 等宽字符
    ~1 字符/token 估。
    """
    chunks: list[str] = []
    system = body.get("system")
    if isinstance(system, str):
        chunks.append(system)
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                chunks.append(block["text"])
    for msg in body.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if isinstance(block.get("text"), str):
                    chunks.append(block["text"])
                elif isinstance(block.get("content"), str):
                    chunks.append(block["content"])
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            chunks.append(json.dumps(tool, ensure_ascii=False))
    text = "\n".join(chunks)
    ascii_n = sum(1 for ch in text if ord(ch) < 128)
    wide_n = len(text) - ascii_n
    return max(1, ascii_n // 4 + wide_n)


@router.post("/v1/messages/count_tokens", dependencies=[Depends(verify_gateway_key)])
async def count_tokens(request: Request):
    """Anthropic 的 token 计数端点（本地估算）。

    Claude Code 在发消息**之前**会先调它做上下文管理 —— 缺了它，客户端在真正发消息那一步
    之前就失败，表现出来就是"Anthropic Messages 这条协议走不通"（2026-09-26 实测：
    /v1/messages 本身返回 200，但这个端点 404）。上游 z.ai 没有对应端点，故本地估算。
    """
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = {}
    if not isinstance(body, dict):
        body = {}
    return {"input_tokens": _estimate_tokens(body)}


@router.post("/v1/messages", dependencies=[Depends(verify_gateway_key)])
async def messages(request: Request):
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": {"message": "请求体不是合法 JSON", "type": "invalid_request"}}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse(
            {"error": {"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}},
            status_code=400,
        )

    incoming_headers = dict(request.headers)
    provider = _detect_provider(body, request.headers)
    body = _normalize_body(body)
    # 验证码页面由本服务托管，端口取实际请求端口（兼容任意启动端口）
    port = request.url.port or settings.PORT

    req_id = secrets.token_hex(8)
    logs.req(req_id, str(body.get("model") or "-"), bool(body.get("stream")), _last_user_text(body))
    reqlog.begin(req_id, "messages", str(body.get("model") or "-"),
                 bool(body.get("stream")), _last_user_text(body))

    try:
        result = await _dispatch(req_id, body, incoming_headers, port, provider)
    except asyncio.CancelledError:
        # 客户端在调度期间断开（429 重试/验证码等待可达数分钟）——CancelError
        # 是 BaseException，不兜底会让监控条目永久滞留「进行中」
        reqlog.finish_error(req_id, "客户端断开", status=499)
        raise
    except Exception as err:  # noqa: BLE001 - 调度层意外异常也要收口监控条目
        reqlog.finish_error(req_id, f"网关内部错误: {err}", status=500)
        return JSONResponse(
            {"error": {"message": "网关内部错误", "type": "internal_error"}},
            status_code=500,
        )
    if isinstance(result, _Upstream):
        # dispatch 返回与流式生成器启动之间的取消窗口：兜底关闭释放并发槽位
        try:
            return result.to_streaming(req_id)
        except asyncio.CancelledError:
            await result.close()
            raise
    return result


@router.post("/v1/chat/completions", dependencies=[Depends(verify_gateway_key)])
async def chat_completions(request: Request):
    try:
        payload = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": {"message": "请求体不是合法 JSON", "type": "invalid_request_error"}}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": {"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}}, status_code=400)

    body, err = openai_to_anthropic(payload)
    if err or body is None:
        return JSONResponse({"error": {"message": err or "请求体不合法", "type": "invalid_request_error"}}, status_code=400)

    incoming_headers = dict(request.headers)
    provider = _detect_provider(body, request.headers)
    body = _normalize_body(body)
    port = request.url.port or settings.PORT

    req_id = secrets.token_hex(8)
    logs.req(req_id, str(body.get("model") or "-"), bool(payload.get("stream")), _last_user_text(body))
    reqlog.begin(req_id, "chat", str(body.get("model") or "-"),
                 bool(payload.get("stream")), _last_user_text(body))

    try:
        result = await _dispatch(req_id, body, incoming_headers, port, provider)
    except asyncio.CancelledError:
        reqlog.finish_error(req_id, "客户端断开", status=499)
        raise
    except Exception as err:  # noqa: BLE001 - 调度层意外异常也要收口监控条目
        reqlog.finish_error(req_id, f"网关内部错误: {err}", status=500)
        return JSONResponse(
            {"error": {"message": "网关内部错误", "type": "internal_error"}},
            status_code=500,
        )
    if not isinstance(result, _Upstream):
        return result

    model = str(body.get("model") or "")
    if payload.get("stream"):
        try:
            return _openai_stream_response(result, model, req_id)
        except asyncio.CancelledError:
            await result.close()
            raise

    try:
        raw = await result.read_body()
        logs.req_ok(req_id)
    except asyncio.CancelledError:
        reqlog.finish_error(req_id, "客户端断开", status=499, t_first=result.t_first)
        raise
    except Exception as err:  # noqa: BLE001
        logs.req_err(req_id, f"读取上游响应失败: {err}")
        reqlog.finish_error(req_id, f"读取上游响应失败: {err}", status=502)
        return JSONResponse({"error": {"message": f"读取上游响应失败: {err}", "type": "upstream_error"}}, status_code=502)
    finally:
        await result.close()
    data = _safe_json(raw.decode("utf-8", "ignore"))
    if not isinstance(data, dict) or data.get("type") != "message":
        reqlog.finish_error(req_id, "上游响应格式异常", status=502, t_first=result.t_first)
        return JSONResponse({"error": {"message": "上游响应格式异常", "type": "upstream_error"}}, status_code=502)
    usage = data.get("usage") or {}
    reqlog.finish_ok(req_id, t_first=result.t_first, status=result.resp.status_code,
                     input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"))
    return JSONResponse(anthropic_to_openai(data, model))


def _responses_stream_response(up: _Upstream, model: str, req_id: str, rid: str, mid: str) -> StreamingResponse:
    """上游 Anthropic SSE -> Responses API 事件序列。

    复用 StreamConverter（Anthropic -> OpenAI delta）后只重新包装事件类型，所以思考链与正文的
    分流规则在三条协议面上完全一致，不需要维护第二套解析。
    """
    conv = StreamConverter(model)
    created = int(time.time())

    async def _iter():
        base = {"id": rid, "object": "response", "created_at": created, "model": model}
        acc: list[str] = []
        try:
            yield "event: response.created\ndata: " + json.dumps({**base, "status": "in_progress", "output": []}) + "\n\n"
            yield "event: response.output_item.added\ndata: " + json.dumps({**base, "output_index": 0, "item": {"id": mid, "type": "message", "status": "in_progress", "role": "assistant", "content": []}}) + "\n\n"
            yield "event: response.content_part.added\ndata: " + json.dumps({**base, "item_id": mid, "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}) + "\n\n"
            async for evt in _sse_events(up):
                for chunk in conv.feed(evt):
                    delta = ((chunk.get("choices") or [{}])[0].get("delta") or {})
                    piece = delta.get("content")
                    if piece:
                        acc.append(piece)
                        yield "event: response.output_text.delta\ndata: " + json.dumps({**base, "item_id": mid, "output_index": 0, "content_index": 0, "delta": piece}) + "\n\n"
                    reasoning = delta.get("reasoning_content")
                    if reasoning:
                        yield "event: response.reasoning_summary_text.delta\ndata: " + json.dumps({**base, "item_id": mid, "output_index": 0, "summary_index": 0, "delta": reasoning}) + "\n\n"
            text = "".join(acc)
            usage = conv.usage or {}
            in_tok, out_tok = usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
            yield "event: response.output_text.done\ndata: " + json.dumps({**base, "item_id": mid, "output_index": 0, "content_index": 0, "text": text}) + "\n\n"
            yield "event: response.completed\ndata: " + json.dumps({**base, "status": "completed", "output": [{"id": mid, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text, "annotations": []}]}], "output_text": text, "usage": {"input_tokens": in_tok, "output_tokens": out_tok, "total_tokens": in_tok + out_tok}}) + "\n\n"
            logs.req_ok(req_id)
            reqlog.finish_ok(req_id, t_first=up.t_first, status=up.resp.status_code,
                             input_tokens=usage.get("prompt_tokens"),
                             output_tokens=usage.get("completion_tokens"))
        except asyncio.CancelledError:
            reqlog.finish_error(req_id, "客户端断开", status=499, t_first=up.t_first)
            raise
        except Exception as err:  # noqa: BLE001
            logs.req_err(req_id, f"流传输中断: {err}")
            reqlog.finish_error(req_id, f"流传输中断: {err}", t_first=up.t_first)
        finally:
            await up.close()

    return StreamingResponse(_iter(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


@router.post("/v1/responses", dependencies=[Depends(verify_gateway_key)])
async def responses(request: Request):
    """OpenAI Responses API —— 与另两条协议共用同一套上游调度（见 _responses_to_openai）。"""
    try:
        payload = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": {"message": "请求体不是合法 JSON", "type": "invalid_request_error"}}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": {"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}}, status_code=400)
    if not payload.get("input"):
        return JSONResponse({"error": {"message": "input 不能为空", "type": "invalid_request_error"}}, status_code=400)

    chat_payload = _responses_to_openai(payload)
    body, err = openai_to_anthropic(chat_payload)
    if err or body is None:
        return JSONResponse({"error": {"message": err or "请求体不合法", "type": "invalid_request_error"}}, status_code=400)

    incoming_headers = dict(request.headers)
    provider = _detect_provider(body, request.headers)
    body = _normalize_body(body)
    port = request.url.port or settings.PORT

    rid = "resp_" + secrets.token_hex(12)
    mid = "msg_" + secrets.token_hex(12)
    req_id = secrets.token_hex(8)
    logs.req(req_id, str(body.get("model") or "-"), bool(payload.get("stream")), _last_user_text(body))
    reqlog.begin(req_id, "responses", str(body.get("model") or "-"),
                 bool(payload.get("stream")), _last_user_text(body))

    try:
        result = await _dispatch(req_id, body, incoming_headers, port, provider)
    except asyncio.CancelledError:
        reqlog.finish_error(req_id, "客户端断开", status=499)
        raise
    except Exception as err:  # noqa: BLE001 - 调度层意外异常也要收口监控条目
        reqlog.finish_error(req_id, f"网关内部错误: {err}", status=500)
        return JSONResponse({"error": {"message": "网关内部错误", "type": "internal_error"}}, status_code=500)

    model = str(body.get("model") or chat_payload.get("model") or "")
    if not isinstance(result, _Upstream):
        return result  # 调度层已给出错误响应（如 503 no_available_account），原样透出
    if payload.get("stream"):
        try:
            return _responses_stream_response(result, model, req_id, rid, mid)
        except asyncio.CancelledError:
            await result.close()
            raise

    try:
        raw = await result.read_body()
        logs.req_ok(req_id)
    except asyncio.CancelledError:
        reqlog.finish_error(req_id, "客户端断开", status=499, t_first=result.t_first)
        raise
    except Exception as err:  # noqa: BLE001
        reqlog.finish_error(req_id, f"读取上游响应失败: {err}", status=502)
        return JSONResponse({"error": {"message": f"读取上游响应失败: {err}", "type": "upstream_error"}}, status_code=502)
    finally:
        await result.close()
    data = _safe_json(raw.decode("utf-8", "ignore"))
    if not isinstance(data, dict) or data.get("type") != "message":
        reqlog.finish_error(req_id, "上游响应格式异常", status=502, t_first=result.t_first)
        return JSONResponse({"error": {"message": "上游响应格式异常", "type": "upstream_error"}}, status_code=502)
    usage = data.get("usage") or {}
    reqlog.finish_ok(req_id, t_first=result.t_first, status=result.resp.status_code,
                     input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"))
    return JSONResponse(_chat_to_responses(anthropic_to_openai(data, model), rid, mid, model))


def _openai_stream_response(up: _Upstream, model: str, req_id: str) -> StreamingResponse:
    """把上游 Anthropic SSE 事件流转换为 OpenAI chunk 流。"""
    conv = StreamConverter(model)

    async def _iter():
        try:
            yield conv.start()
            # 事件来源统一走 _sse_events：上游忽略 stream（体被业务码嗅探预读）时，
            # 它会把那份 JSON 还原成等效事件，而不是让我们迭代一个已读空的流。
            async for evt in _sse_events(up):
                for out in conv.feed(evt):
                    yield out
            yield conv.done()
            logs.req_ok(req_id)
            reqlog.finish_ok(req_id, t_first=up.t_first, status=up.resp.status_code,
                             input_tokens=conv.usage.get("prompt_tokens"),
                             output_tokens=conv.usage.get("completion_tokens"))
        except asyncio.CancelledError:
            reqlog.finish_error(req_id, "客户端断开", status=499, t_first=up.t_first)
            raise
        except Exception as err:  # noqa: BLE001
            logs.req_err(req_id, f"流传输中断: {err}")
            reqlog.finish_error(req_id, f"流传输中断: {err}", t_first=up.t_first)
        finally:
            await up.close()

    return StreamingResponse(_iter(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


async def _dispatch(req_id, body, incoming_headers, port, provider):
    """多账号轮询调度：_Upstream（成功）或 JSONResponse（错误）。

    单账号并发限制：选号后若该账号在飞请求已达上限（store.account_concurrency，
    0 = 不限），跳过换下一个账号——不排队（流式请求可占槽位数分钟，排队会
    放大延迟甚至吊死客户端）。满号跳过不计入 MAX_ACCOUNT_ATTEMPTS（只计真正
    进入 _try_account 的次数）。全满/无号 → 503。
    """
    tried: set[str] = set()
    limit = _limit()
    attempts = 0

    while attempts < MAX_ACCOUNT_ATTEMPTS:
        account = store.select(provider, skip_ids=tried)
        if account is None:
            break
        tried.add(account.id)
        if limit > 0 and _inflight.get(account.id, 0) >= limit:
            logs.warn(req_id, f"账号 {account.name} 并发已满（{_inflight.get(account.id, 0)}/{limit}），切换下一个")
            continue
        attempts += 1
        needs_captcha = provider == "zai" and account.uses_plan_channel()

        slot_box: list[str | None] = [None]
        if limit > 0:
            _inflight[account.id] = _inflight.get(account.id, 0) + 1
            slot_box[0] = account.id
        try:
            result = await _try_account(
                req_id, account, body, incoming_headers, port, needs_captcha, slot_box,
            )
        except BaseException:
            if slot_box[0] is not None:
                _release_slot(slot_box[0])
                slot_box[0] = None
            raise
        if result is _NEXT_ACCOUNT:
            if slot_box[0] is not None:
                _release_slot(slot_box[0])
                slot_box[0] = None
            continue
        if isinstance(result, _Upstream):
            held = slot_box[0]
            slot_box[0] = None
            if held is not None:
                result.on_close = _make_slot_releaser(held)
            return result
        if slot_box[0] is not None:
            _release_slot(slot_box[0])
            slot_box[0] = None
        return result

    logs.req_err(req_id, "无可用账号 / 额度均已耗尽 / 并发已满")
    reqlog.finish_error(req_id, "无可用账号 / 额度均已耗尽 / 并发已满", status=503)
    return JSONResponse(
        {"error": {"message": "所有账号均不可用、额度已用完或并发已满，请在后台检查账号状态", "type": "no_available_account"}},
        status_code=503,
    )


def _release_slot(account_id: str) -> None:
    n = _inflight.get(account_id, 0) - 1
    if n <= 0:
        _inflight.pop(account_id, None)
    else:
        _inflight[account_id] = n


def _park_slot(slot_box: list[str | None] | None) -> None:
    """等待（429/验证码/5xx）前释放并发槽，避免把账号冻住数分钟。"""
    if slot_box and slot_box[0] is not None:
        _release_slot(slot_box[0])
        slot_box[0] = None


def _reacquire_slot(account: Account, slot_box: list[str | None] | None) -> bool:
    """等待结束后重新占槽；占不到则让调用方换号。"""
    if slot_box is None:
        return True
    limit = _limit()
    if limit <= 0:
        return True
    if _inflight.get(account.id, 0) >= limit:
        return False
    _inflight[account.id] = _inflight.get(account.id, 0) + 1
    slot_box[0] = account.id
    return True


def _make_slot_releaser(account_id: str):
    def _release() -> None:
        _release_slot(account_id)
    return _release


_NEXT_ACCOUNT = object()


# fire-and-forget 后台任务强引用：事件循环对 task 只持弱引用，裸 create_task
# 会被 GC 中途静默丢弃（同 main.py 启动安装序已修过的缺陷，2026-09 review）。
_bg_tasks: set[asyncio.Task] = set()


def _spawn_bg(coro) -> None:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


# 账号并发限制：account_id → 在飞请求数。asyncio 单线程事件循环下
# check+inc 原子；释放走 _Upstream.close / 失败路径，泄漏面在测试钉住。
_inflight: dict[str, int] = {}


def _limit() -> int:
    """当前并发上限（0 = 不限），实时读取设置（后台改后即生效）。"""
    return store.account_concurrency()


class _Upstream:
    """已建立的上游成功流：由调用方消费并负责关闭。"""

    __slots__ = ("resp", "cm", "client", "t_first", "account_name", "mode", "on_close", "_closed",
                 "preloaded")

    def __init__(self, resp: httpx.Response, cm, client: httpx.AsyncClient,
                 t_first: float | None = None, account_name: str = "", mode: str = "",
                 on_close=None, preloaded: bytes | None = None) -> None:
        self.resp = resp
        self.cm = cm
        self.client = client
        self.t_first = t_first
        self.account_name = account_name
        self.mode = mode
        self.on_close = on_close
        self._closed = False
        # 业务码嗅探已把非 SSE 响应读完的体（见 _sniff_business_error）：调用方
        # 必须从这里取，不能再迭代 resp 的流。
        self.preloaded = preloaded

    async def read_body(self) -> bytes:
        """完整响应体：已预读时直接交付缓存，否则读上游流。"""
        if self.preloaded is not None:
            return self.preloaded
        return await self.resp.aread()

    async def close(self) -> None:
        """幂等关闭：释放上游流与并发槽位（on_close），重复调用安全。"""
        if self._closed:
            return
        self._closed = True
        await self.cm.__aexit__(None, None, None)
        # 共享客户端不在这里关：退出流上下文就已把连接归还池（这正是复用的意义）。
        await _release_client(self.client)
        if self.on_close is not None:
            try:
                self.on_close()
            except Exception:  # noqa: BLE001 - 槽位释放失败不掩盖主流程
                pass

    def to_streaming(self, req_id: str) -> StreamingResponse:
        """原样透传（/v1/messages 直通路径）。"""
        up = self

        async def _body_iter():
            try:
                if up.preloaded is not None:
                    yield up.preloaded      # 体已被嗅探读走，流里已无内容
                else:
                    async for chunk in up.resp.aiter_bytes():
                        yield chunk
                logs.req_ok(req_id)
                reqlog.finish_ok(req_id, t_first=up.t_first, status=up.resp.status_code)
            except asyncio.CancelledError:
                reqlog.finish_error(req_id, "客户端断开", status=499, t_first=up.t_first)
                raise
            except Exception as err:  # noqa: BLE001
                logs.req_err(req_id, f"流传输中断: {err}")
                reqlog.finish_error(req_id, f"流传输中断: {err}", t_first=up.t_first)
            finally:
                await up.close()

        return StreamingResponse(_body_iter(), status_code=up.resp.status_code,
                                 media_type=up.resp.headers.get("content-type", "application/json"),
                                 headers={"Cache-Control": "no-cache"})


def _preloaded_sse_events(raw: bytes) -> list[dict]:
    """把"上游忽略 stream 参数、直接回了 200 JSON"的那份响应体还原成 Anthropic SSE 事件。

    为什么需要：`_sniff_business_error` 在 2xx 时预读整个响应体判业务码，读走之后
    上游流里已经没有任何内容。流式路径靠 `conv.feed(evt)` 吃饭，若直接去迭代那个
    空流，客户端会收到一个"有头无正文"的流（只 start + done），而 reqlog 还记成功。
    """
    data = _safe_json(raw.decode("utf-8", "ignore"))
    if not isinstance(data, dict):
        return []
    head = {k: v for k, v in data.items() if k != "content"}
    events: list[dict] = [{"type": "message_start", "message": head}]
    for idx, block in enumerate(data.get("content") or []):
        if not isinstance(block, dict):
            continue
        events.append({"type": "content_block_start", "index": idx, "content_block": block})
        if block.get("type") == "text" and block.get("text"):
            events.append({"type": "content_block_delta", "index": idx,
                           "delta": {"type": "text_delta", "text": block["text"]}})
        events.append({"type": "content_block_stop", "index": idx})
    events.append({"type": "message_delta",
                   "delta": {"stop_reason": data.get("stop_reason"), "stop_sequence": None},
                   "usage": data.get("usage") or {}})
    events.append({"type": "message_stop"})
    return events


async def _sse_events(up: "_Upstream"):
    """流式路径的统一事件来源：正常情况下逐行读上游 SSE；体已被预读走时走还原路径。"""
    if up.preloaded is not None:
        for evt in _preloaded_sse_events(up.preloaded):
            yield evt
        return
    async for line in up.resp.aiter_lines():
        if not line.startswith("data:"):
            continue
        evt = _safe_json(line[5:].strip())
        if isinstance(evt, dict):
            yield evt


async def _try_account(req_id, account, body, incoming_headers, port, needs_captcha,
                       slot_box: list | None = None):
    """尝试用单个账号转发，含验证码续期与可配置重试。

    错误处理策略（参数见 settings，均可用环境变量调整）：
      - 验证码挑战：清池换码重建请求，最多 MAX_CAPTCHA_RETRIES 次
      - 429 频控：**不冷却账号**，按上游 Retry-After（封顶 RETRY_429_WAIT_MAX）
        或 RETRY_429_WAIT 等待后原地重试，最多 RETRY_429_TIMES 次；
        耗尽后换下一个账号，账号保持可用。Plan 通道耗尽且有 API Key 时切
        回退通道重试（force_fallback 显式路由——429 不改账号状态，不能靠
        status 推导通道；回退通道自己的 429 重试预算独立计满后再换号）
      - 5xx 等一般错误：重试最多 RETRY_5XX_TIMES 次；耗尽后账号冷却
        COOLING_SECONDS 并换下一个账号
      - 风控（3012/405「unusual activity」真封禁）：直接禁用账号（UI 展示），
        人工确认恢复后手动启用，不做自动退避
    """
    captcha_retries = 0
    retries_429 = 0
    retries_5xx = 0
    force_fallback = False  # 本请求瞬态走 Key 回退（不改账号持久化状态）
    model_name = str(body.get("model") or "-")
    while True:
        attempt_t0 = time.time()
        reqlog.mark_account(req_id, account.name, account.mode)
        verify_param = verify_region = None
        token_obj = None   # 本轮持有的池内 token；被挑战时 on_challenge 精确丢它
        if needs_captcha:
            _park_slot(slot_box)
            try:
                token_obj = await captcha_manager.acquire_token(port)
            except Exception as err:  # noqa: BLE001
                logs.req_err(req_id, f"人机校验失败: {err}")
                reqlog.finish_error(req_id, f"人机校验失败: {err}", status=500)
                return JSONResponse(
                    {"error": {"message": f"无法完成人机校验: {err}", "type": "captcha_error"}},
                    status_code=500,
                )
            verify_param, verify_region = token_obj.param, token_obj.region
            if not _reacquire_slot(account, slot_box):
                logs.warn(req_id, f"账号 {account.name} 验证码等待后并发已满，切换下一个")
                return _NEXT_ACCOUNT

        try:
            url, headers, payload = build_request(account, body, verify_param,
                                                  incoming_headers, verify_region,
                                                  force_fallback=force_fallback)
        except RuntimeError as err:
            account.record_result(False, f"凭证无效: {err}")
            _mark(account, Status.INVALID, str(err))
            logs.warn(req_id, f"账号 {account.name} 凭证无效，切换下一个")
            return _NEXT_ACCOUNT

        client = _client()
        cm = client.stream("POST", url, headers=headers, content=payload)
        try:
            resp = await cm.__aenter__()
        except httpx.HTTPError as err:
            await _release_client(client)
            account.record_result(False, f"连接失败: {err}")
            # 废 JWT / 风控禁用走 Key 回退失败时不得洗成 cooling，否则冷却结束会重开 Plan
            if account.status in (Status.INVALID, Status.DISABLED):
                store.update_account(account)
            else:
                _mark(account, Status.COOLING, f"连接失败: {err}")
            logs.warn(req_id, f"账号 {account.name} 连接失败，切换下一个")
            return _NEXT_ACCOUNT

        status_code = resp.status_code
        preloaded: bytes | None = None

        if status_code < 400:
            # 200 里的业务错误（额度 / 风控 / 验证码 / 未知码）归一化成等效状态码，
            # 落到下面同一套分支处理。漏掉这一步，start-plan 的 1005 会以
            # 「HTTP 200 + ok=True」被静默吞掉：客户端收到假成功、账号不换、
            # 额度回来了也没人知道。
            normalized, preloaded = await _sniff_business_error(resp)
            if normalized is not None:
                logs.warn(
                    req_id,
                    f"账号 {account.name} HTTP 200 业务错误 -> 按 {normalized} 处理: "
                    f"{preloaded.decode('utf-8', 'ignore')[:200]}",
                )
                status_code = normalized

        if status_code >= 400:
            text = (preloaded if preloaded is not None else await resp.aread()).decode("utf-8", "ignore")
            await cm.__aexit__(None, None, None)
            await _release_client(client)

            # 验证码挑战：只丢引发挑战的那一枚（连续挑战才升级全清，见
            # captcha.on_challenge），下一轮从池里取新枚重试。verifyParam 一次性
            # （probe_3007_isolation.py 实验 C），换枚是必然动作。
            challenge = _detect_captcha_challenge(resp, text) if needs_captcha else None
            if challenge:
                captcha_manager.on_challenge(token_obj)
                captcha_retries += 1
                if captcha_retries >= MAX_CAPTCHA_RETRIES:
                    account.record_result(False, "验证码挑战连续失败")
                    logs.warn(req_id, f"账号 {account.name} 验证码连续失败，切换下一个")
                    return _NEXT_ACCOUNT
                logs.warn(req_id, f"账号 {account.name} 验证码挑战（{challenge}），刷新重试")
                continue  # 同账号重建请求重试

            # 风控（3012「unusual activity」/ 405）：真封禁 → 禁用账号，人工恢复。
            # 必须先于 exhausted/其它错误判定，且不再重试（避免对封禁账号持续施压）。
            if _is_risk_control(status_code, text):
                account.record_result(False, f"风控封禁 HTTP {status_code}（3012/unusual activity）")
                account.ban_for_risk()
                account.last_error = (
                    f"风控封禁 (3012/unusual activity) HTTP {status_code}，"
                    f"确认恢复后请在后台手动启用（第 {account.risk_strikes} 次）"
                )
                store.update_account(account)
                if needs_captcha and account.has_apikey_fallback():
                    logs.warn(
                        req_id,
                        f"账号 {account.name} 命中风控 HTTP {status_code}，已禁用 Plan 通道"
                        f"（累计第 {account.risk_strikes} 次），切 API Key 回退",
                    )
                    needs_captcha = False
                    force_fallback = True
                    continue
                logs.warn(
                    req_id,
                    f"账号 {account.name} 命中风控 HTTP {status_code}，已禁用"
                    f"（累计第 {account.risk_strikes} 次），切换下一个",
                )
                return _NEXT_ACCOUNT

            if _is_exhausted(status_code, text):
                account.record_result(False, f"额度用完 HTTP {status_code}")
                if account.status in (Status.INVALID, Status.DISABLED):
                    store.update_account(account)
                else:
                    _mark(account, Status.EXHAUSTED, "额度已用完")
                    _spawn_bg(_safe_refresh(account))
                logs.warn(req_id, f"账号 {account.name} 额度用完，切换下一个")
                return _NEXT_ACCOUNT

            if status_code == 401:
                account.record_result(False, "鉴权失败 HTTP 401")
                _mark(account, Status.INVALID, "鉴权失败 HTTP 401")
                if needs_captcha and account.has_apikey_fallback():
                    logs.warn(req_id, f"账号 {account.name} 鉴权失败 401，切 API Key 回退")
                    needs_captcha = False
                    force_fallback = True
                    continue
                logs.warn(req_id, f"账号 {account.name} 鉴权失败 401，切换下一个")
                return _NEXT_ACCOUNT

            if status_code == 403:
                # 403 已排除挑战形态（上方 challenge 分支），此处为真实鉴权拒绝
                account.record_result(False, "鉴权失败 HTTP 403")
                _mark(account, Status.INVALID, "鉴权失败 HTTP 403")
                if needs_captcha and account.has_apikey_fallback():
                    logs.warn(req_id, f"账号 {account.name} 鉴权失败 403，切 API Key 回退")
                    needs_captcha = False
                    force_fallback = True
                    continue
                logs.warn(req_id, f"账号 {account.name} 鉴权失败 403，切换下一个")
                return _NEXT_ACCOUNT

            if status_code == 429:
                # 频控不是账号故障：不冷却，原地等一等再试，耗尽后换号且账号保持可用。
                # Plan 通道耗尽 ≠ Key 回退也耗尽：同账号切回退并归还该通道的重试预算
                #（与上方 3012/401/403 切回退同一语义）
                if retries_429 < settings.RETRY_429_TIMES:
                    retries_429 += 1
                    wait = _parse_retry_after(resp.headers.get("retry-after")) or settings.RETRY_429_WAIT
                    logs.warn(
                        req_id,
                        f"账号 {account.name} 被限流 429，{wait}s 后重试"
                        f"（{retries_429}/{settings.RETRY_429_TIMES}）",
                    )
                    _park_slot(slot_box)
                    await _sleep(wait)
                    if not _reacquire_slot(account, slot_box):
                        logs.warn(req_id, f"账号 {account.name} 429 等待后并发已满，切换下一个")
                        return _NEXT_ACCOUNT
                    continue
                if needs_captcha and account.has_apikey_fallback():
                    account.record_result(False, "Plan 通道 429 耗尽，切 API Key 回退")
                    logs.warn(req_id, f"账号 {account.name} Plan 通道 429 耗尽，切 API Key 回退")
                    needs_captcha = False
                    force_fallback = True
                    retries_429 = 0
                    continue
                account.record_result(False, f"429 重试 {settings.RETRY_429_TIMES} 次耗尽")
                store.update_account(account)
                logs.warn(
                    req_id,
                    f"账号 {account.name} 429 重试 {settings.RETRY_429_TIMES} 次耗尽，"
                    f"切换下一个（账号保持可用）",
                )
                return _NEXT_ACCOUNT

            if status_code >= 500:
                # 一般性上游错误：重试，耗尽才冷却账号并换号
                if retries_5xx < settings.RETRY_5XX_TIMES:
                    retries_5xx += 1
                    logs.warn(
                        req_id,
                        f"账号 {account.name} 上游 HTTP {status_code}，"
                        f"{settings.RETRY_5XX_WAIT}s 后重试（{retries_5xx}/{settings.RETRY_5XX_TIMES}）",
                    )
                    _park_slot(slot_box)
                    await _sleep(settings.RETRY_5XX_WAIT)
                    if not _reacquire_slot(account, slot_box):
                        logs.warn(req_id, f"账号 {account.name} 5xx 等待后并发已满，切换下一个")
                        return _NEXT_ACCOUNT
                    continue
                account.record_result(False, f"HTTP {status_code} 重试 {settings.RETRY_5XX_TIMES} 次耗尽，冷却")
                if account.status in (Status.INVALID, Status.DISABLED):
                    # Key 回退 5xx 不得覆盖废 JWT / 风控禁用，否则冷却结束会重开 Plan
                    store.update_account(account)
                    logs.warn(req_id, f"账号 {account.name} 上游 {status_code} 重试耗尽，Plan 已停用，切换下一个")
                else:
                    cool = settings.COOLING_SECONDS
                    account.status = Status.COOLING
                    account.cooling_until = time.time() + cool
                    account.last_error = f"上游 HTTP {status_code} 重试 {settings.RETRY_5XX_TIMES} 次耗尽，冷却"
                    store.update_account(account)
                    logs.warn(req_id, f"账号 {account.name} 上游 {status_code} 重试耗尽，冷却 {cool}s，切换下一个")
                return _NEXT_ACCOUNT

            # 其它 4xx：直接回传客户端；响应体全量落日志供排查
            # （错误 JSON 通常很小；防御性上限 4KB，超长按 HTML 类 WAF 页处理只留头部）
            account.fail_count += 1
            account.record_result(False, f"HTTP {status_code}: {text[:120]}".replace("\n", " "))
            store.update_account(account)
            logs.req_err(req_id, f"上游错误 HTTP {status_code}（账号 {account.name}）")
            body_log = text if len(text) <= 4000 else text[:4000] + f"...(共 {len(text)} 字节，疑似 WAF 页)"
            logs.warn(req_id, f"上游 {status_code} 完整响应体: {body_log}")
            reqlog.finish_error(req_id, f"HTTP {status_code}: {text[:120]}".replace("\n", " "),
                                status=status_code, t_first=time.time() - attempt_t0)
            return JSONResponse(
                _safe_json(text) or {"error": {"message": text[:500], "type": "upstream_error"}},
                status_code=status_code,
            )

        # 成功：记录用量并把打开的上游流交给调用方
        if needs_captcha:
            captcha_manager.note_accept()
        account.use_count += 1
        account.last_used_at = time.time()
        account.record_result(True, f"HTTP 200 · {model_name} · {time.time() - attempt_t0:.1f}s")
        # API Key 回退成功不得把废 JWT / 风控禁用洗成 active，也不得清风控计数
        if account.status not in (Status.INVALID, Status.DISABLED):
            account.risk_strikes = 0
            account.last_error = None
            account.cooling_until = None
            account.exhausted_until = None
            if account.status in (Status.COOLING, Status.EXHAUSTED):
                account.status = Status.ACTIVE
        # 热路径只登记脏标记，5s 内合并落库（store.touch_account）：每请求一次
        # 同步落库会在事件循环上串行占全局锁，是并发下的下一个瓶颈。状态类
        # 变更（冷却/封禁/额度）仍走 update_account 即时落，见 _mark 各分支。
        store.touch_account(account)
        _spawn_bg(_safe_refresh(account))

        return _Upstream(resp, cm, client, t_first=time.time() - attempt_t0,
                         account_name=account.name, mode=account.mode,
                         preloaded=preloaded)


def _safe_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


async def _safe_refresh(account: Account) -> None:
    try:
        live = store.find(account.provider, account.id)
        if live is None:
            return
        if live.provider == "zai" and live.allows_billing():
            # 去抖：每条消息都刷 billing 是流量放大器（会加剧风控），与 monitor 共享
            # last_checked_at，最小间隔内的刷新直接跳过
            last = live.last_checked_at
            if last and time.time() - last < settings.BILLING_REFRESH_MIN_INTERVAL:
                return
            await fetch_quota(live)
    except Exception:  # noqa: BLE001
        pass
