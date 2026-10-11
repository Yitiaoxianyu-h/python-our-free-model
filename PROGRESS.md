# 移植进度（Python 版 Our Free Model）

> 规则：每完成一项立即更新本文件，避免后续 AI 重复或遗漏。
> 原版参考：`old/dsh-our-free-model-main`（Node.js，DSH 插件，v2.0.0）

## 目标
把 DSH「Our Free Model」插件移植为 **Python 独立本地服务**：
- 后端 Python（FastAPI + uvicorn + httpx）
- 前端 Web UI（原生 HTML/CSS/JS，无构建步骤）
- 双击 `start.bat` 启动，黑框打印 Web UI 地址（Ctrl+左键打开）
- 核心：把免费模型映射到本地端口，供第三方 Agent 通过 OpenAI 兼容接口接入

## 运行方式
```powershell
# 双击（首次会自动建 venv 并装依赖，全部在项目目录内）
start.bat
# 或手动
cd backend
.\.venv\Scripts\python.exe run.py            # 默认 http://127.0.0.1:18900
.\.venv\Scripts\python.exe run.py --port 18900 --probe   # 启动即探测
```

## 已完成 ✅
- [x] 通读并梳理原版核心：免费车道、Kilo、EAC、13 渠道、转发口、SSE 解析、工具指纹、思考预算、可用性探测、断流恢复
- [x] 项目骨架：`backend/`、`frontend/`、`start.bat`、`PROGRESS.md`
- [x] 依赖安装到项目内 venv（`.venv`），`PIP_CACHE_DIR` 指向项目，不占 C 盘
- [x] `ofm/paths.py`：数据目录（默认项目内 `data/`，`OFM_HOME`/`--data-dir` 可覆盖）
- [x] `ofm/store.py`：JsonStore + 设置/统计/探测 + 用量统计 + 解码窗口 + 迁移
- [x] `ofm/upstream.py`：会话/请求 id 铸造、工具指纹、端点分流、请求头
- [x] `ofm/http_client.py`：请求投递、SSE 读取、body 形状嗅探、失败分类、TLS（系统证书库 + `OFM_TLS_VERIFY`）
- [x] `ofm/channel.py`：单生产者/单消费者异步通道
- [x] `ofm/stream.py`：三线协议解码、DSML 清洗、usage 映射、块协议
- [x] `ofm/messages.py`：消息投影（chat/messages/responses）+ 工具配对修复 + 工具定义
- [x] `ofm/effort.py`：思考档位 → 输出预算 + 声明式 effort 菜单
- [x] `ofm/catalog.py`：能力表、目录构建（免费 / Kilo / EAC）
- [x] `ofm/recovery.py`：断流/空停续写策略、检查点、块追踪
- [x] `ofm/kilo.py`：Kilo 免费池（清单 + 流式投递）
- [x] `ofm/probe.py`：可用性探测 + 出口 IP/国家检测
- [x] `ofm/eac.py`：EAC 保险库/闸门框架（无密封材料时渠道整体不存在）
- [x] `ofm/adapter.py`：FreeModelAdapter.run_stream 完整主流程（含恢复续写、指纹、Kilo/EAC 分流）
- [x] `ofm/runtime.py`：模型运行时 + 成员计算 + 目录/可用性刷新 + 出口监视
- [x] `ofm/completion.py`：OpenAI 请求投影 + 结果折叠 + 用量换算
- [x] `ofm/forward.py`：OpenAI 兼容端点（chat/responses，流式 + 非流式，工具重编号与诱饵抑制，心跳）
- [x] `ofm/service.py`：FastAPI 应用、管理 API、鉴权门、后台刷新/探测循环、静态前端
- [x] `ofm/run.py`：启动器（端口顺延 + 打印 Web UI 地址）
- [x] `frontend/`：Web UI（概览 / 游乐场 / 模型清单 / 白嫖渠道 / EAC / 用量统计 / 日志 / 服务设置 / API 接入）
- [x] `start.bat`：双击启动（首次自动建 venv 装依赖）
- [x] `ofm/channels/`：渠道框架
  - `store.py`：凭据存储（0600）+ 账号池（启用/模型级限流/永久积分锁定/优先级）
  - `base.py`：渠道元数据基类 + `OpenAICompatChannel`（标准 OpenAI 兼容上游流式适配器）
  - `registry.py`：15 条渠道注册表（2 条免密车道已接入 + 13 个账号渠道待移植）
- [x] 管理 API `GET /api/management/channels`，前端「白嫖渠道」页从接口渲染
- [x] **CodeArts（华为云）渠道已移植**（原版顺序第 1 家）
  - `ofm/channels/huawei_sign.py`：SDK-HMAC-SHA256 请求签名（canonical request / string-to-sign / Authorization）
  - `ofm/channels/codearts.py`：PKCE、DPoP(ES256 JWS)、OAuth 浏览器登录（本地回调 ≥10000 端口）+ 旧 ticket 回退、
    refresh_token 续期、两个签名 GET 拉取模型目录（benefit 判定 + VL 过滤 + `-NNNN` 归一化）、
    签名 POST `/api/v2/chat/completions` + SSE(chat wire) 推理、401/403 自动续期重试
  - `ofm/channels/manager.py`：渠道管理器（按模块约定自动加载各渠道 / 目录并入主目录 / 推理分派 / 登录生命周期）
  - 主链路接线：目录合并（`channel_catalog`）、推理分派（`channel_stream`）、登录 API
    `POST|GET /api/management/channels/{id}/login`，前端渠道卡片带「登录 / 新建账号」按钮
  - 已验证：签名、PKCE、DPoP（EC P-256，JWS 535 字符）、登录 URL、服务启动与渠道列表
- [x] **CodeBuddy（腾讯）渠道已移植**（原版顺序第 2 家）——`ofm/channels/buddy.py`（副 Agent 产出，已验收）
- [x] **WorkBuddy（腾讯国际版）渠道已移植**（原版顺序第 3 家）——`ofm/channels/workbuddy.py`（副 Agent 产出，已验收）
- [x] **LobsterAI（有道）渠道已移植**（原版顺序第 4 家）——`ofm/channels/lobsterai.py`（副 Agent 产出，已验收）
- [x] **Cline 渠道已移植**（原版顺序第 8 家）——`ofm/channels/cline.py`（副 Agent 产出，已验收）
- [x] **Gemini 渠道已移植**（原版顺序第 13 家）——`ofm/channels/gemini.py`（本次自行实现，已自测）
  - Google OAuth（本地回调 + state + offline/consent）、凭据续期；五个写死的 antigravity 身份头 + Bearer；
    流式**不带 Accept**；两层信封 `{model,project,request}` 且**逐层字母序序列化**；
    `/v1internal:streamGenerateContent?alt=sse` 帧解析；`thoughtSignature` 落盘与回填（`gemini-sigs.json`）；
    静态模型 `gemini-3.8-flash` 四档思考（low/medium/high/tiered）；schema 白名单清洗；图片 inlineData（10MB 上限）
  - 自测通过：字母序序列化、档位映射、schema 清洗、请求翻译（role user/model/user、functionResponse、tools、
    thinkingBudget=1000、systemInstruction）、图片内联
  - 四家（buddy/workbuddy/lobsterai/cline）均通过：compileall、import、模块约定签名一致、
    `fetch_models({})` 兜底表可用（16 / 23 / 19 / 24 个模型）
- [x] **账号管理 API + 界面**：`GET /api/management/accounts`、`POST /accounts/{id}/enabled`、`POST /accounts/{id}/delete`；
  渠道页新增「已登录账号」表格（启用开关 / 删除）
- [x] **渠道调用计入用量看板**：转发层对账号渠道调用记录 usage（origin = channel:&lt;id&gt;）
- [x] **局域网转发中继**——`ofm/lan_relay.py`
  - 独立监听（默认 0.0.0.0）+ 独立 Key；每请求鉴权；仅放行 /v1 三条路径；跳数标记 508 防自环；本机 Key 换入再转发
  - 设置页可开关 / 改端口 / 查看与轮换中继 Key / 显示可拨通地址；管理 API
    `GET /api/management/forward/lan`、`/lan/key`、`POST /lan/rotate`、`/lan/addresses`
  - 已验证：中继端口 61901，带 LAN Key → 26 个模型；无 Key → 401；用本机 Key → 401；非白名单 → 404
- [x] **端到端验证通过**：
  - `GET /health` → 200；`GET /v1/models` 无 Key → 401，有 Key → 模型列表
  - `POST /v1/chat/completions`（非流式）→ 真实上游返回 `OK`，usage 正常
  - `POST /v1/chat/completions`（流式）→ 200，149 个 SSE 帧
  - 目录发现 28 个免费模型，探测标记 16 个 available
  - `GET /` 与 `/static/*` 正常返回；`GET /api/management/channels` 返回 15 条渠道

- [x] **MiniMax Code 渠道已移植**（原版顺序第 11 家）——`ofm/channels/minimax.py`（本次自行实现，已自测）
  - OAuth 设备码 + PKCE(S256)（client_id `mcode-public` / audience `agent-backend` / scope `agent.default`）、refresh_token 续期；
    推理走 **Anthropic Messages**：`POST https://agent.minimax.cn/mavis/api/v1/llm/v1/messages`，
    头只带 Authorization + Content-Type + Accept（**不发 anthropic-version**）；
    SSE 事件流（thinking_delta / text_delta / input_json_delta，**signature_delta 忽略**）；
    图片 `image.source.base64`；HTTP 402 = 余额不足 → QUOTA_EXCEEDED
  - 自测通过：4 条兜底模型、请求翻译（system/images/tool_use/tool_result）、思考规则（M3.1 强制 adaptive、
    M2.7 不发 thinking）、usage/stop 映射、SSE 消费（thinking/text/tool_use → tool-calls）
- [x] **ZCode**（第 12 家）——`ofm/channels/zcode.py`（本次自行实现，已自测）
  - CLI 设备授权流登录（`/api/v1/oauth/cli/init` → 浏览器 → `poll/{flow_id}`）；`device_mid` 本地随机；**不可续期**；
  - 推理走 Anthropic Messages（`/api/v1/zcode-plan/anthropic/v1/messages`）；
  - **身份块是 3012 准入唯一开关**：system = CLI 前缀(42) + stable 三段 + Environment + 调用方，
    实测合计 2898 字符（原版记录 ~2900）；首轮 user 前置 `<system-reminder>` 日期块；最后一块打 cache_control；
  - 工具扁平 `input_schema`，思考走 `output_config.effort`；错误码 3007→验证码（本移植无浏览器，抛明确提示）、
    3012→风控不重试、401/1002→重新登录、1113→余额不足；
  - 自测通过：身份块长度与结构、日期块、请求构造、错误分类、SSE 消费
- [x] **Loomy（讯飞）**（第 9 家）——`ofm/channels/loomy.py`（副 Agent 产出，已验收）
  - **分步登录**：`start_login()` 发短信验证码 / `submit_login({phone|code})`（本项目新增的交互式登录契约）
  - 兜底表 8 条；`fetch_models` / `stream` 符合模块约定
- [x] **Raccoon Work（商汤）**（第 10 家）——`ofm/channels/raccoon.py`（副 Agent 产出，已验收）
  - **分步登录**：`start_login()` 生成真实二维码（SVG dataURL）+ 短信兜底；`submit_login()` 轮询扫码结果或提交手机号/验证码
  - 兜底表 6 条；`refresh_credential` / `stream` 符合模块约定；实测 `start_login()` 返回
    `{status: awaiting-code, qr: data:image/svg+xml;base64,...}`
- [x] **全部 15 条渠道已接入（15/15）**：匿名免费车道、Kilo、CodeArts、CodeBuddy、WorkBuddy、LobsterAI、
  Qoder、Qoder 中国版、TRAE、Cline、Loomy、Raccoon、MiniMax、ZCode、Gemini
  - 最终验证：`GET /api/management/channels` → READY 15/15，PENDING 为空；
    免费车道目录 28 个模型 / 23 个可用；局域网中继 running=True
- [x] **请求日志（Web UI「日志」页）**——`ofm/logs.py` + 埋点 + 管理 API + 前端
  - `ofm/logs.py`：`RequestLog` = 内存 `deque(maxlen=500)` + `data/logs.jsonl` 追加持久化
    （启动读尾部并重写裁剪）；列表接口**剔除** request/response 预览，详情接口才返回（各自截断 2000 字符）。
  - `ofm/completion.py`：唯一转发漏斗统一埋点，**成功 / 渠道内错误 / 抛异常**三条路径都写日志；
    记录 at/model/channel/stream/ok/status/code/error/errorType/latencyMs/ttftMs(in-out-reasoning-cacheRead)/truncated + 请求/响应预览。
  - 管理 API：`GET /api/management/logs?model=&errors=1&limit=&offset=`（返回 items/total/limit/stored/failed/models）、
    `GET /api/management/logs/{id}`（含预览详情）、`POST /api/management/logs/clear`。
  - 前端：导航新增「日志」；页面含模型下拉筛选、只看错误开关、刷新、清空；列表失败行显示状态码与错误摘要，
    点行/「详情」展开请求与响应预览（此时才请求详情接口）。
- [x] **在线游乐场（Web UI「游乐场」页）**
  - 后端 `POST /api/management/playground/chat`（仅回环管理接口，无需 API Key）：接收 `{model, messages, temperature?, max_tokens?, reasoning_effort?}`，
    在服务端构造 OpenAI 请求交给同一个 `self.complete` 转发漏斗，并以**精简 SSE** 回给浏览器：
    `{"delta"}` / `{"reasoning"}` / `{"tool"}` / `{"error"}` / `{"done":true,"usage",…}` + 末尾 `data: [DONE]`；
    带 15s 心跳与 abort 传播（`_playground_stream` 在 service.py 末尾）。
  - 前端：选模型后**自动填充配置**——上下文窗口/输出上限（`#pg-maxtokens` 取 min(maxOutput, 默认上限)）、
    思考档位（`efforts` 菜单或 light/balanced/deep）、是否支持图片/思考都写在模型元信息里；
    支持系统提示词、温度、输出上限、流式逐字显示与思考内容折叠显示、停止、清空对话、多轮历史。
  - **思考链可复开**：思考内容（`reasoning`）随助手消息一起存入历史，用 `<details>` 渲染——
    流式中实时展开并显示「思考中…（N 字）」，结束后自动折叠为可点击的「思考链（N 字）」，
    之后无论后台刷新重建对话区还是重新发送，都能随时点开查看（此前思考链只活在当时的气泡里，完成后即丢失）。
- [x] **API Key 校验方式**（设置项 `forwardKeyMode`：`auto`（默认，自动生成的 Key 必填）/ `custom`（用户自定义 Key）/ `off`（不校验，任意或空 Key 均放行））
  - `_v1_gate`：仅当模式为 `off` 时跳过校验，其余仍严格比对 `forwardKey`。
  - `_settings_post`：新增 `forwardKeyMode` 与 `forwardKey`（自定义时写入，空则在 custom 模式下报 400）。
  - 前端「API 接入」页新增「校验方式」下拉 + 自定义 Key 输入 + 保存；`_settings_view.forward.keyMode` 回读。
  - 注意：**局域网中继 Key 独立**，不受 `forwardKeyMode` 影响（LAN 是网络暴露面，保留独立 Key）。
- [x] **修复：隐藏状态下复制 API Key 复制到圆点**
  - 原来 `data-copy="#access-key"` 读的是被掩码的 `••••••••`；改为 `data-copy-secret="access"|"lan"`，
    点击时先调 `/api/management/forward/key`（或 `/forward/lan/key`）取**真实 Key** 再写剪贴板，与是否显示无关。
- [x] **Git 接入：新增根目录 `.gitignore`**（仅创建规则文件，未执行 `git init`，由使用者自行初始化）
  - 排除个人信息/凭据：`/data/`——含 `settings.json` 的 `forwardKey`/`forwardLanKey`、`eac/user.json` 的 GitHub 授权令牌、请求日志与用量/目录缓存。
  - 排除 `/old/`——原版 DSH 插件的 TypeScript 参考源码，不属于本项目实现。
  - 排除本机产物：`.venv/`、`.pip-cache/`、`__pycache__/`、`*.py[cod]`、`*.log`、`logs.jsonl`、`service.lock`、`.env*`。
  - 排除个人 IDE 配置：`.trae/`、`.vscode/`、`.idea/`。
  - 保留代码与文档：`backend/`、`frontend/`、`start.bat`、`PROGRESS.md`、`requirements.txt`、`README`（如有）。

## 已知边界（如实说明）
- **登录/推理未逐家真机验证**：本机没有各渠道账号，`run_login` / `start_login` 与真实 SSE 回包
  未做端到端实测（严格照原版 TS 逐行移植）。免费车道（OpenCode Zen）与 Kilo 已用真实上游验证。
- **Qoder** 依赖 `wasmtime` 驱动官方 WASM 生成 COSY 签名（已装并可加载）；签名算法本身不可逆向。
- **ZCode** 推理不需要验证码（3.14.4 起）；若被 3007 拒，本移植无浏览器，会抛明确提示。
- **ZCode/Raccoon/Loomy** 的积分领取、自动签到等「渠道内附加功能」未移植（登录 + 模型目录 + 推理已具备）。
- **EAC 协付渠道（已按原版实现，可用）**：
  - 原版凭据是 AES-256-GCM 密文；密钥由**三片掩码分片**（两片在 `src/vault-data.js`、一片在
    `src/vault-anchor.js`）用 `HKDF-SHA256(seed, salt=pepper, info='shard-mask')` 异或解掩码后派生
    （`HKDF-SHA256(拼接三片, salt='ofm-lane-seal/1\\x00co-paid\\x00desktop-only', info='seal-open/ aes-256-gcm/ per-request')`）。
  - 本移植**把密文材料原样搬进** `ofm/eac_vault_data.py`（明文仍不存在于仓库），并在
    `ofm/eac_vault.py` 复刻同一套派生/解密 —— 解锁得到**仓库自带的 EAC 网关**
    （`worker` 模式，签名网关 `…/eac/v1`）。宿主播判定保留为 `standalone`（本服务即分发宿主）。
  - 请求签名与原版逐字一致：`x-ofm-signature = HMAC-SHA256(signKey, "{ts}\\n{METHOD}\\n{path}\\n{sha256hex(body)}")`，
    另有 `x-ofm-user`（GitHub 授权令牌）；端点 `GET /models`、`POST /chat/completions`、`GET /pool`。
  - **GitHub 授权按原版流程**（`src/eac-login.js`）：EAC 页点「用 GitHub 授权」→
    `GET {root}/auth/github/start?link=`（302）→ 系统浏览器打开 → 用户登录 + star →
    本机轮询 `GET {root}/auth/poll?link=&retain=1`（`pending`/`unstarred`/`expired`/`ok`）→
    拿到令牌写入 `data/eac/user.json`（0600），必要时回 `POST /auth/ack`。
  - 管理 API：`GET /eac`、`POST /eac/login/start`、`GET /eac/login/poll`、`POST /eac/logout`、
    `GET /eac/pool`、`POST /eac/gateway`（高级：自建网关覆盖内置凭据）、`POST /eac/gateway/clear`。
  - **实测**：解密成功（mode=worker）；签名 GET 拉到**真实 6 个模型**
    （deepseek-ai/deepseek-v4.1-flash、moonshotai/kimi-k2.6、moonshotai/kimi-k3、
    openai/gpt-oss-20b、z-ai/glm-5.3、z-ai/glm-5.3-flash）；授权入口返回可打开的 `/eac/auth/github/start?link=`；
    未授权时对话返回 `502 eac: 需要 GitHub 授权（网关返回 401）；请在 EAC 页面完成授权`。
  - 修复：`/eac/login/start` 与 `/eac/login/poll` 里漏写 `self.`（`NameError` → HTTP 500），已改为
    `self._sealed_credential()`；EAC 页「车道」卡的副标题由「内置密封凭据 · worker」简化为 `worker`。


- [x] **Qoder / Qoder 中国版**（第 5、6 家）——`ofm/channels/qoder.py`、`qodercn.py`（副 Agent 产出，已验收）
  - 设备码 + PKCE 登录、凭据续期、兜底表（国际 17 / 中国 14 条）
  - 关键：官方 `qoder-auth-wasm.wasm` 的 wasm-bindgen 桥已用 **wasmtime** 复刻，实测可产出
    `Authorization: Bearer COSY.<payload>.<sig>` 与真实加密端点；签名密钥派生不可逆，故除调 WASM 外没有第二条签名路径。
    **已把 wasmtime 加入 requirements**；`signer_status()` 实测 `available: True`
- [x] **TRAE**（第 7 家）——`ofm/channels/trae.py`（副 Agent 产出，已验收）：ExchangeToken 轮换、Cloud-IDE-JWT 鉴权、
  SOLO 载荷转换、自定义 SSE 解析；兜底表 28 条
- [x] **交互式登录契约**：渠道模块可实现 `start_login()` / `submit_login(payload)`（短信/扫码分步），
  管理器与前端（验证码输入框 / 二维码渲染）已支持
- [x] **待完成（3 条）**：Loomy、Raccoon（副 Agent 进行中，分步登录）、ZCode（依赖 chromium 验证码）

## 进行中
- [ ] 13 个账号渠道逐家移植（剩余 6 条）

## 待办
- [ ] 各渠道登录流程（浏览器/设备码/短信）、积分领取、渠道原生模型目录
- [ ] 渠道本地 OpenAI 网关中继（`chan-gateway`）
- [ ] 局域网转发中继（第二道门 + 独立 Key）
- [ ] EAC 密封材料解锁后的签名请求与资源池代理
- [ ] 公告 feed / 自更新 / 热重载（原版针对 DSH 宿主，独立服务中不适用，改为可选项）

## 关键决策与差异（重要，勿重复踩坑）
- **局域网中继端口被占用不再拖垮主服务**：`LanRelay.start()` 改为**自己先 bind** 再把 socket 交给 uvicorn
  （旧写法让 uvicorn 的 `Server.startup` 在端口冲突时调 `sys.exit(3)`，SystemExit 冒到事件循环会**把整个进程连主服务一起带走**）。
  配置端口被占时自动退到系统分配端口并如实记日志；刻意不设 `SO_REUSEADDR`（Windows 上会让冲突检测失效）。
- **同一数据目录只允许一个实例**：`run.py` 用 `data/service.lock`（写入 pid + url）判重，已有活跃实例时打印
  「已经在运行了 + 地址 + PID」并直接退出；强制关闭留下的**陈旧锁**会被自动忽略并覆盖，不会挡住下次启动。
- **`start.bat` 必须是 CRLF 换行 + 纯 ASCII 内容**：cmd.exe 不认 LF 换行，且 `chcp 65001` 生效前
  中文会被当作命令解析 → 双击直接闪退。已修正（64 行全 CRLF、无 BOM、无中文）。
  若后续用工具改这个文件，改完必须重新转成 CRLF（PowerShell 一行即可），不要留 LF。
  另：脚本每次启动会先自检依赖（`import fastapi,uvicorn,httpx,pydantic,cryptography`），
  缺了才重装，失败即 `pause` 停住 —— 不会再把「首次安装」文案误报成「缺依赖」。
  注：`wasmtime` 只服务 Qoder，属可选依赖，不在自检清单里（缺失不会触发重装）。
- **单一端口**：管理页与 `/v1/*` 同一端口（默认 18900，占用自动顺延）。原版插件另有独立转发口，此处合并。
- **数据目录**：默认项目内 `data/`（原版 `~/.our-free-model`），避免污染 C 盘。
- **TLS**：httpx 默认用 certifi，本机存在中间证书时握手失败；已改为 `ssl.create_default_context()`
  （Windows 加载系统根证书）。仍不行可设 `OFM_TLS_VERIFY=0` 关闭校验。
- **系统代理**：本机若设置了 `HTTP_PROXY` 等，httpx 会把 `127.0.0.1` 也走代理导致 404；
  测试本地接口时用 `trust_env=False` 或设 `NO_PROXY=127.0.0.1`。
- **EAC**：无密封材料/私密网关，未提供时渠道整体不存在（与原版命令行行为一致）。
  用户可放 `data/eac/sealed.json` 启用。
- **13 渠道**：原版 `vendor/channel-pack` 为 159 文件 / ~4MB TS（OAuth、设备码、短信、
  ZCode 的 chromium 验证码、Qoder WASM）。逐家移植是超大工程，按渠道框架 → 单渠道推进。

## 测试记录
- 编译：`python -m compileall ofm` 全通过
- 导入：全部模块可导入
- 上游清单：`GET /zen/v1/models` 成功（系统证书库生效后）
- 真实对话（非流式）：`nemotron-3.5-lightning-free` → "OK"，usage prompt 21 / completion 150 / reasoning 141
- 真实对话（流式）：149 帧正常
- 请求日志（测试实例 `--no-refresh --data-dir data-logtest`，端口 18990）：
  - `GET /api/management/logs`（空）→ `{items:[],stored:0}`；`GET /{id}` 详情含请求预览
  - 失败：`POST /v1/chat/completions {model:"no-such-model"}` → 落库 `ok:false,status:404,errorType:NotFound`
  - 成功：`POST /v1/chat/completions {model:"mimo-v2.6-flash-free"}` → 上游回 "OK"，落库
    `ok:true,status:200,latencyMs:4950,ttftMs:4932,input:223,output:13,reasoning:10,cacheRead:192`
  - `POST /api/management/logs/clear` → `{ok:true}`，之后列表归零、`data/logs.jsonl` 被删除
  - `GET /` 含 `data-page="logs"` 导航；`/static/app.js` 含 `renderLogs`
- 游乐场 + API Key 校验方式（测试实例 `--no-refresh --data-dir data-pgtest`，端口 18991）：
  - Key 模式：`auto` 无 Key→401 / 错 Key→401 / 对 Key→200（8 个模型）；切 `off` 后无 Key→200；
    切 `custom`+`forwardKey=my-custom-key-123` 后带该 Key→200、旧 Key→401；custom 空 Key→400
  - 游乐场：`POST /api/management/playground/chat` → 200，`content-type: text/event-stream`，
    34 个 data 帧（含 `{"reasoning"}`、`{"delta"}`、结尾 `{"done":true,"usage":{...}}` 与 `data: [DONE]`）
  - 静态页：`GET /` 含 `data-page="playground"`、`data-copy-secret="access"`、`id="key-mode"`；
    `/static/app.js` 含 `sendPlayground`、`data-copy-secret`
