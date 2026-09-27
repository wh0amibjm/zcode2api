# 05 — 上游协议参考

状态：定稿（三个来源项目实测 + 公开配置验证）。所有端点已在 zcode2api / zcode-switch / zcode-api 中观测到真实流量。

## 1. 端点拓扑

```
认证:    chat.z.ai/api/oauth/authorize        (浏览器授权)
         zcode.z.ai/api/v1/oauth/token        (授权码换 access_token)
         zcode.z.ai/api/v1/oauth/cli/init     (CLI 发起, server-mediated)
         zcode.z.ai/api/v1/oauth/cli/poll/{flow_id}
         chat.z.ai/api/oauth/userinfo         (Bearer access_token)
         api.z.ai/api/auth/z/login            (access_token → 业务 JWT)

AI:      zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages   (Plan 通道, Bearer JWT)
         api.z.ai/api/anthropic/v1/messages                   (API Key 通道, x-api-key)
         open.bigmodel.cn/api/anthropic/v1/messages           (BigModel, x-api-key)

计费:    zcode.z.ai/api/v1/zcode-plan/billing/current   ⚠️ WAF
         zcode.z.ai/api/v1/zcode-plan/billing/balance   ⚠️ WAF
         api.z.ai/api/biz/subscription/list             ✅
         api.z.ai/api/monitor/usage/quota/limit         ✅
         zcode.z.ai/api/v1/client/configs               ✅ 免鉴权

领取:    zcode.z.ai/api/v1/zcode-plan/billing/preview
         zcode.z.ai/api/v1/zcode-plan/billing/claim

风控:    zcode.z.ai/api/v1/agent/configs                (endpoint routing + 签名开关)
```

⚠️ WAF：实测会拦截非浏览器特征的 `billing/current|balance` 访问——**错峰轮询 + 完整身仿真头是硬要求**，`fetch_quota` 对 401 需先排除验证码挑战再判凭证失效。

## 2. 认证链路

### 2.1 zai OAuth（CLI server-mediated，headless 友好）

```
1. POST zcode.z.ai/api/v1/oauth/cli/init
   Headers: Authorization: Bearer <本地随机 poll_token>, Content-Type: application/json
   Body:    {"provider": "zai"}
   → data.{flow_id, authorize_url}
2. 浏览器打开 authorize_url（chat.z.ai/api/oauth/authorize?client_id=client_P8X5CMWmlaRO9gyO-KSqtg&...）
3. GET zcode.z.ai/api/v1/oauth/cli/poll/{flow_id}   (Bearer poll_token，轮询至授权完成)
   → data.accessToken（含过期时间）+ zcodejwttoken（视返回结构）
4. POST api.z.ai/api/auth/z/login  {"token": "<access_token>"}  → 业务 JWT
5. GET  chat.z.ai/api/oauth/userinfo (Bearer access_token)      → user_id
6. 兑换 API Key：getCustomerInfo(默认机构/项目) → api_keys(name="zcode-api-key") → copy/{key} 取 secretKey
```

桌面客户端（对照）：redirect_uri 为 `zcode://zai-auth/callback`，本地 HTTP 服务器接 code 后走 `POST /api/v1/oauth/token`（`{provider:"zai", code, redirect_uri, state}`）。

### 2.2 bigmodel OAuth

```
authorize: https://bigmodel.cn/login?redirect={REDIRECT_ENC}&appId=zcode&state={p}
回调:      zcode://oauth/callback (桌面) / 本地回调端口（CLI 实现）
token 交换: zcode.z.ai/api/v1/oauth/token
业务侧:    bigmodel.cn 域（getCustomerInfo / api_keys），API 形态同 zai
```

## 3. 对话请求（Plan 通道，start-plan 需验证码）

```http
POST https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages
Authorization: Bearer {zcodejwttoken}
anthropic-version: 2023-06-01
Content-Type: application/json
User-Agent: ZCode/{app_version}
X-ZCode-App-Version: {app_version}
X-ZCode-Agent: glm
HTTP-Referer: https://zcode.z.ai/
X-Title: Z Code@{sourceTitle}
X-Device-Mid: {uuidv4，首次生成永久复用}
X-Aliyun-Captcha-Verify-Param: {verifyParam}        # start-plan 必需
X-Aliyun-Captcha-Region: {region}
```

Body：标准 Anthropic Messages（`model/max_tokens/stream/system/messages`）。上游模型名**大小写敏感**（`GLM-5.2`、`GLM-5-Turbo`）。

API Key 通道差异：`x-api-key: {apiKey}.{secret?}` 替代 Bearer，无验证码头。

**验证码 verifyParam**：Node+jsdom 运行阿里云官方无痕 SDK（`AliyunCaptcha.js`，o.alicdn.com），`startTracelessVerification()` 成功回调给出 `verifyParam = base64(JSON{certifyId, sceneId, isSign, securityToken})`；sceneId/region/prefix 从 `client/configs` 动态取（默认 `11xygtvd/sgp/no8xfe`）。挑战形态：403 + captcha 头；或 400 + body `{"code":3007}`。

**被拒信号**（池分类依据）：

| 上游响应 | 判定 | 动作 |
|----------|------|------|
| 402 / body 含 quota|insufficient|balance|exhaust|额度|余额不足 | 额度耗尽 | exhausted，30min 重试窗 |
| 429 | 限流 | cooling 300s |
| 401 / 403(非验证码) | 凭证失效 | invalid，直到重登 |
| 403 + captcha 挑战 / 400+`code:3007` | 验证码问题 | 刷新 verifyParam 原账号重试 |
| **HTTP 200** + body 业务码 —— `{"code":1005,"msg":"exceed quota limit"}`（2026-09-26 实测） | 额度耗尽，**与状态码无关，看体里的 code** | 归一化成 `402` 后走同一分支：标 `exhausted`（带 30min 试探窗）+ 换号 |

**200 里带业务码这一形态必须单独处理**：只判 `status_code >= 400` 的实现会把它当成功 ——
`recent_results` 记 `ok=True`、账号不换、客户端收到「200 但体不是 message」的响应，额度回来那天
也没有任何东西知道。实测形态是**流式请求也回 JSON**（`content-type: application/json`，不是
`text/event-stream`），所以按 content-type 排除 SSE 后预读一次即可覆盖两个路径；判定口径与真实
4xx 同源（额度→402 / 风控→405 / 验证码→400 / 未知业务码→502），不存在第二套分类逻辑。
**额度是日窗口**，耗尽时 `billing/current` 与 `billing/balance` 都会回落成空数组 —— 即「数字恢复」
这条路径消失，故 `exhausted` 必须自带时间窗（`ZCODE_EXHAUST_RETRY_SECONDS`，默认 1800s），
到期放回池子试一次，成功由成功分支的 `EXHAUSTED→ACTIVE` 收口。

## 4. 免费额度（Start Plan）

`GET zcode.z.ai/api/v1/client/configs?app_version={ver}`（免鉴权）→ `data.configs.startPlanPreview`：

| 模型 | 日额度 |
|------|--------|
| GLM-5.3（旗舰，原名 GLM-5.2，服务端可换 showName） | 3,000,000 tokens/日 |
| GLM-5-Turbo（≈Sonnet 级） | 2,000,000 tokens/日 |

独立计算、每日重置；额度由服务端按账号在调用时授予与扣减。`billing/balance` 返回 `data.balances[]`（`show_name/model/total_units/used_units/remaining_units/expires_at`）——即 PlanSlot 数据源。

## 5. 领取（活动套餐）

```
GET  billing/preview   → data.previews[]: ClaimPlan{plan_id,name,description,priority,grants,grant_items[{name,units,period}]}
                          （活动未上线时 404 —— 属正常态，静默跳过）
                          查询参数: app_version 必带；platform 参数 preview 容忍、client/configs 拒绝（3001）
POST billing/claim     → 头: Bearer JWT + 验证码头 + X-Device-Mid + X-ZCode-App-Version + X-Platform
                          （实测缺版本/平台头即使验证码有效也 3007 —— asar claimManualPlan 头形态）; body: {plan_id}
                          成功 → starts_at/ends_at 生效窗口
                          失败码: already_claimed / quota_exhausted → 按服务端 next window 退避
前置: identity.appVersion ≥ 活动要求的最低客户端版本（否则 ineligible）
```

版本口径（单一真相源 `app/constants.py`）：`CLIENT_APP_VERSION="3.11.2"`；
无账号路径的 `CLIENT_PLATFORM="darwin-arm64"`（asar `TH()` = `process.platform-process.arch`）。
有账号时 `X-Platform` / preview `platform` 跟该号 DeviceProfile 走（成套桌面 SKU，一号一台），禁止再盖成全局 darwin-arm64。
`USER_AGENT` / `X-ZCode-App-Version` / configs 查询串全部引用版本常量。

## 6. 免费额度以外的两条通道（认知备查）

| 通道 | 计费 | 端点 | 认证 |
|------|------|------|------|
| API Key 通道 | 用户 BigModel/Z.ai API Key 按量 | `open.bigmodel.cn/api/anthropic` / `api.z.ai/api/anthropic` | `x-api-key` |
| Plan 通道（免费 Start + 付费 Coding） | ZCode 账号额度 | `zcode.z.ai/api/v1/zcode-plan/anthropic` | `Bearer JWT` |

## 7. 风控开关（Phase 4 备查，源自 zcode-api 观测）

- **endpoint routing**：`GET agent/configs` → `data.proxyEndpoint.mapping`（coding-plan Anthropic 端点被映射到 `zcode.z.ai/api/v1/ultra[-zai]/...`）；客户端定期拉取并重写上游 URL，fail-open。
- **client signing V4**：`agent/configs` → `data.codingPlanSignature.enable=true` 时，coding-plan 请求需先握手 `{provider}/api/paas/c1f3a7e2/v2/client`，随后每请求附 Ed25519 签名 + PoW 头；连续两次 401 VERIFY 后进入永久 unsigned 旁路（客户端行为）。start-plan / off-peak 永不免签。

## 8. 客户端身份头完整集（仿真必备）

```json
{
  "User-Agent": "ZCode/{appVersion}",
  "X-ZCode-App-Version": "{appVersion}",
  "X-ZCode-Agent": "glm",
  "X-Platform": "{platform}-{arch}",
  "X-Os-Category": "{osCategory}",
  "X-Release-Channel": "stable",
  "X-Client-Language": "{locale}",
  "X-Client-Timezone": "{timezone}",
  "X-Title": "Z Code@{sourceTitle}",
  "HTTP-Referer": "https://zcode.z.ai/",
  "X-Device-Mid": "{稳定 UUIDv4}"
}
```

`appVersion` 必须可打印 ASCII，非法值静默回退默认；`X-Device-Mid` 永不逐请求随机（防指纹抖动）。

### 8.1 追踪头（通道相关，别按「官方发了就跟着发」推）

| 通道 | `x-request-id` | `x-zcode-session-type` | `x-zcode-trace-id` | `x-query-id` / `x-session-id` |
|------|----------------|------------------------|--------------------|-------------------------------|
| **Plan（start-plan，Bearer JWT）** | ✅ 每请求新值 | ✅ `main` | ✅ 每请求新值 | ❌ **不发** |
| API Key（coding-plan） | — | — | — | 按 zapi 记录会发（`build_trace_headers(plan="coding-plan")`） |

- Plan 通道的追踪头**恒为三件套**。`x-query-id` / `x-session-id` 在该通道上是上游的
  风控信号，不是可自由启用的缓存钥匙 —— 误发触发 3012（2026-09-27 事故，见 §9）。
- 下游塞进来的同名头由 `agent._DROP_HEADERS` 剔除，不透传；客户端不发**不能**当作保证。
- 生成点是 `identity.build_trace_headers()`，Plan 分支在 `agent.build_request()` 里调用。
  `plan="coding-plan"` 分支当前**无调用点**（只保留了通道差异的记录），删改它不影响线上行为，
  但它是那条差异的唯一落点 —— 要动先读 §9。
- 「官方开源 CLI 对所有请求都发 `x-session-id`」**不构成**本通道可以发的依据：那是官方客户端
  身份下的行为，与本网关镜像的 start-plan 形态在上游眼里不是一回事。
- 同理，调研里对 coding-plan **签名路径**做的会话/缓存对照也只能停在它自己那条通道：那条路径上
  `X-Session-Id` 是签名与 PoW 的输入（协议字段），端点是 `/api/coding/paas/v4/chat/completions`、
  认证是 `Bearer <api_key>` —— 端点、认证、头集与 Plan 通道全不同。把它的结论搬过来，就是
  2026-09-27 那次事故的直接原因。**跨通道外推不成立**，这比「结论本身对不对」更要紧。

## 9. 事故档案（脱敏）

按时间倒序。每条只记**机制、结论、回归锁定**：不写账号标识、凭证、主机名、路径与部署细节。
结论必须落到可执行规则上并配回归用例 —— 否则同一个理由会被再犯一次。

### 2026-09-28 — 3012 有两种语义：模型级拦截被当成账号级风控，五个请求打光整池

**现象**：某模型（`GLM-5.3`，非 Flash）的请求全部 `405 + {"code":3012,"msg":"...unusual activity..."}`，
而**同一账号、同一时刻、同一枚新解验证码的 `GLM-5.3-Flash` 正常 200**。`ban_for_risk()` 把命中账号
置 DISABLED（该分支按设计不自愈），触发窗口 5 分钟内 20/21 个账号全部 disabled —— 而它们对 Flash 全健康。

**判据**（正反两种顺序、两个冷账号）：

| 臂 | 模型 | 结果 |
|---|---|---|
| 同账号，先打被拦模型 | `GLM-5.3` | 405 · `code=3012` |
| 紧接同账号 | `GLM-5.3-Flash` | **200 出话** |
| 另一个冷账号，反序 | Flash → `GLM-5.3` | **200** → 405 |
| 同账号 | `GLM-5.2` | 400 · `code=3006 model not allowed`（模型不允许走的是另一条码） |
| 裸最小 body / 带官方身份块 / 小写模型名 | `GLM-5.3` | 全部 3012 ⇒ **与请求体形态无关，只看模型名** |

额度单里该模型的日窗口（`model:glm-5.3`，未过期）仍然下发：**额度单承认这个模型，但上游策略
不放行** —— 所以它没走 3006 那条路，直接落 3012。热账号（用量高的那种）连 Flash 也 3012，
那是反复 3012 之后账号真被上游盯上的**后果**，不是原因。

**结论 / 规则**：

1. `405 + 3012` 有两种语义，**不能一律判账号级**：模型级（账号健康）与账号级（账号被盯上）。
   判级手段：命中 3012 后用**同账号**补发一发 Flash 探针（`constants.RISK_PROBE_MODEL`），
   探针 200 即证明账号健康。
2. 判级无据（探针 5xx / 取码失败）时**冷却，不封号**：误封不自愈、误冷却会自愈 ——
   与「403 不再无条件判 invalid」同一条既有修正。
3. 模型级命中的处置是**熔断模型**（`ZCODE_MODEL_BLOCK_SECONDS`，默认 900s，到期自动再试），
   熔断期内同模型请求在 `_dispatch` 就被拒（400 `model_blocked`），零上游流量、零验证码消耗。
   退出开关 `ZCODE_MODEL_BLOCK_PROBE=0` 退回旧行为做对照。
4. 被误杀的账号用 `POST /admin/api/accounts/risk-reset` 批量放回；该接口只认
   `enabled=True 且 DISABLED` 的风控形态，后台手动停用的号不会被顺手打开。
5. 这条与 2026-09-27 那条是**同一个错误码的两个不同原因**，结论不可互相搬用：
   09-27 是请求头形态触发的真风控，09-28 是模型维度的策略拦截。

**回归锁定**：`tests/integration/test_gateway_model_block.py`（12 条，覆盖账号级/模型级/判级无据
三态、熔断期零上游流量、大小写归一、误杀复位）+ `tests/unit/test_model_block.py`（5 条状态机）。
mock 上游新增 `risk_control_3012_by_model` 场景（按 payload 里的模型名决定是否返 3012），
判级探针的落点由此可断言。

### 2026-09-27 — Plan 通道加 `x-session-id`，池内大面积 3012

**动机**：官方开源 CLI（`zai-org/ZCode`，`runner-attribution.ts`）对每个模型请求都带
`x-session-id`（会话级稳定）+ `x-query-id` + `x-request-id`，其注释说服务端靠这些头区分
main/subagent/other。据此推断「start-plan 不发 `x-session-id`」这条旧结论已被**证伪**，
并进一步假设上游**前缀缓存按 session 分桶**：固定 session 时 `cached_tokens` 从第 2 轮起稳定命中，
随机则恒 miss。于是做了三件事：① Plan 通道改发会话级稳定的 `x-session-id` / `x-zcode-trace-id`
（派生口径：下游鉴权身份 + model + system + 首条 user 消息的哈希；下游显式给 `X-Session-Id` 则采用）；
② 加了按会话粘账号的调度（同一会话固定打同一账号，保住缓存分桶身份）；③ 留了
`ZCODE_SESSION_HEADERS=0` 回退开关。

**结果**：上线后**数分钟内**，池内绝大多数账号（12 个里 11 个）吃到
`3012 unusual activity`（HTTP 405）。`Account.ban_for_risk()` 把命中账号置 `Status.DISABLED`，
而该分支**按设计不自动恢复**（人工确认后才 `set_enabled`）—— 一次错误的头形态，换来一个人工恢复的号池。
回滚（代码 + 重启 + 清风控计数）后，观察窗内未再见 3012。

**结论**：

1. 「官方客户端/官方开源实现发了这个头」≠「本网关可以发」。官方 CLI 是官方客户端身份；
   本网关镜像的是 start-plan 请求形态。**跨实现推断头形态，必须先在网关自身形态上验证。**
2. `x-session-id` / `x-query-id` 是 Plan 通道的**风控信号**，不是缓存钥匙。头形态见 §8.1。
3. **缓存那条依据是跨通道错位引用**（比「没测过」更危险）：当时引用的「固定 session 从第 2 轮起
   `cached_tokens` 确定性命中」，原始测量发生在 **coding-plan 签名路径**上 —— 端点
   `/api/coding/paas/v4/chat/completions`、认证 `Bearer <api_key>`，而且 `X-Session-Id` 在那里
   **是 Ed25519 签名与 PoW 的输入**（签名串与 `proof_of_work` 都含 `session_id`），即它是该通道的
   **协议字段**，不是可以搬用的归因头。原始记录自身还标着「不是确定性开关」「分桶机制为推断、
   未在客户端侧证实」，复跑出现过 3/5 的不稳定结果。⇒ 搬到 Plan 通道属于**跨通道外推**。
   要论证本通道的缓存命中，先在**不改头形态**的前提下拿到可重复的 `cached_tokens` 对照数据。
4. **回滚是止损，不是完整归因**：同批账号里有一个在事故窗口内仍正常服务过一轮，所以头形态
   未必是唯一触发条件（并发量、身份指纹同样是候选）。若 3012 在回滚后复发，往身份头完整性与
   并发方向查，别回头再咬这一行。
5. 事故期间被 `ban_for_risk` 置 DISABLED 的账号**不会自愈**，回滚后需人工 `set_enabled`
   并清 `risk_strikes` —— 排障时先看这两项，别把「禁用未恢复」误判成「还在被风控」。

**回归锁定**：`tests/unit/test_plan_channel_headers.py`（9 条，含集成层断言**上游实际收到的头**）。
已做变异验证：把 `x-session-id` 加回 `build_trace_headers()` 的 start-plan 分支，
单测 `test_start_plan_branch_does_not` 与集成 `test_upstream_sees_no_incident_headers`
等 5 条同时变红 —— 该守卫不是同义反复。

**这次事故不成立的修法记录**（避免有人重走）：加头 + 会话粘性账号 + 回退开关这套改动本身
在代码层面是自洽的，`_SESSION_AFFINITY` 的粘性路由与 `derive_session` 的派生口径也都能用；
**错的只有「Plan 通道可以带这两个头」这一条前提**。要复用这份工作，只能用在被证明接受
这两个头的通道上，且先在 §8.1 登记通道差异。
