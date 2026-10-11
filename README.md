# Our Free Model（Python 版）

把多个免费/白嫖 AI 渠道的模型，**映射到本机一个端口**，用 **OpenAI 兼容接口**对外提供服务，
让任意第三方 Agent / 客户端直接接入使用；同时自带一个网页控制台（模型清单、在线游乐场、渠道登录、
用量统计、请求日志等）。

> 本项目是 [dsh-our-free-model](https://github.com/Ebony-Vinyl/dsh-our-free-model)（原版 DSH 插件，TypeScript）
> 的 **Python 移植版**：后端用 FastAPI 重写，前端改为零构建的原生 HTML/CSS/JS 控制台。
> 原项目地址：**https://github.com/Ebony-Vinyl/dsh-our-free-model**

---

## 目录

- [特性](#特性)
- [环境要求](#环境要求)
- [快速开始（如何启动）](#快速开始如何启动)
- [打开 Web 控制台](#打开-web-控制台)
- [接入第三方 Agent](#接入第三方-agent)
- [API Key 校验方式](#api-key-校验方式)
- [Web 控制台功能](#web-控制台功能)
- [局域网共享](#局域网共享)
- [启动参数](#启动参数)
- [环境变量](#环境变量)
- [目录结构](#目录结构)
- [常见问题](#常见问题)
- [已知边界](#已知边界)
- [免责声明](#免责声明)

---

## 特性

- **OpenAI 兼容**：`GET /v1/models`、`POST /v1/chat/completions`、`POST /v1/responses`（流式 / 非流式、工具调用）。
- **单一端口**：网页控制台与 `/v1/*` 同一个端口（默认 `18900`，被占用自动顺延）。
- **在线游乐场**：在浏览器里直接和模型对话，选中模型会**自动填充**上下文、输出上限、思考档位等配置。
- **多渠道**：内置 15 条渠道（免费车道 + 账号渠道），账号渠道支持浏览器 / 设备码 / 短信登录与账号池。
- **EAC 车道**：内置密封凭据，按原版流程用 GitHub 授权（登录 + star 仓库）后解锁。
- **用量统计 & 请求日志**：按模型汇总调用量；每次转发的成功/失败都留档，失败能看清错在哪。
- **局域网共享**：可选开一个独立端口的中继，让同网络的其它设备也能用（独立 Key）。
- **数据不出项目目录**：虚拟环境、pip 缓存、运行时数据全部落在项目文件夹内（不占 C 盘）。

---

## 环境要求

- **Windows**（启动脚本为 `.bat`；服务本身跨平台，手动运行即可在 macOS/Linux 启动）。
- **Python 3.10+**（推荐 3.11/3.12/3.13），且已加入 `PATH`。
- 首次启动会自动把依赖安装到项目内的 `backend/.venv`，**无需手动装到系统 Python**。

依赖清单见 [backend/requirements.txt](backend/requirements.txt)：`fastapi`、`uvicorn`、`httpx`、`httpx-socks`、`pydantic`、`cryptography`，以及可选的 `wasmtime`（仅 Qoder 渠道需要）。

---

## 快速开始（如何启动）

### 方式一：双击启动（推荐）

1. 进入项目根目录，**双击 `start.bat`**。
2. 首次运行会自动：创建虚拟环境 `backend/.venv` → 安装依赖（缓存写入 `backend/.pip-cache`）。
3. 启动成功后，会弹出一个黑色命令行窗口，里面会打印：

   ```
   ====================================================================
     Our Free Model 2.0.0  —  本地免费模型转发服务
   ====================================================================
     Web UI 控制台:  http://127.0.0.1:18900
     OpenAI 兼容地址: http://127.0.0.1:18900/v1
     数据目录:       ...\python-our-free-model\data
   ```

4. **按住 `Ctrl` 并点击那个 `http://127.0.0.1:18900` 地址**，即可在浏览器打开网页控制台。
5. 关闭这个黑框窗口（或按 `Ctrl+C`）即停止服务。

> 端口 `18900` 若被占用，会自动往后找到可用端口（`18901`、`18902`…），以黑框里打印的地址为准。

### 方式二：命令行手动启动

```bat
cd /d "d:\编程项目\python\python-our-free-model"

REM 1) 创建虚拟环境（只需执行一次）
python -m venv backend\.venv

REM 2) 安装依赖（只需执行一次）
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

REM 3) 启动服务
backend\.venv\Scripts\python.exe backend\run.py
```

macOS / Linux 手动启动：

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
backend/.venv/bin/python backend/run.py
```

### 已启动但想再开一个

同一数据目录**只允许一个实例**（用 `data/service.lock` 判重）。若重复启动，会提示"已经在运行了"并给出当前地址。
要并行跑第二个实例，请换端口 + 换数据目录：

```bat
start.bat --port 18910 --data-dir "d:\ofm-second"
```

---

## 打开 Web 控制台

浏览器访问黑框里打印的地址（默认 <http://127.0.0.1:18900>）。
控制台只在**本机**可访问（管理接口仅回环可达）。

---

## 接入第三方 Agent

在控制台「**API 接入**」页可以看到 **Base URL** 和 **API Key**：

- Base URL：`http://127.0.0.1:18900/v1`
- API Key：点「显示」查看，点「复制」复制（**即使处于隐藏状态，复制到的也是真实 Key**）。

### curl 示例

```bash
curl http://127.0.0.1:18900/v1/chat/completions ^
  -H "Authorization: Bearer <你的 API Key>" ^
  -H "Content-Type: application/json" ^
  -d "{\"model\":\"<模型 id>\",\"messages\":[{\"role\":\"user\",\"content\":\"你好\"}],\"stream\":true}"
```

### Python（OpenAI SDK）示例

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:18900/v1",
    api_key="<你的 API Key>",
)

resp = client.chat.completions.create(
    model="<模型 id>",  # 用 GET /v1/models 获取可用 id
    messages=[{"role": "user", "content": "你好"}],
)
print(resp.choices[0].message.content)
```

### 任意 OpenAI 兼容客户端

把 **Base URL** 填 `http://127.0.0.1:18900/v1`、**API Key** 填控制台里那个 Key，模型名填
「模型清单」页里任一可用模型即可。

---

## API Key 校验方式

在「**API 接入**」页可以切换校验方式（保存后立即生效）：

| 模式 | 说明 |
| --- | --- |
| **自动生成（默认）** | 使用本机自动生成的 API Key，客户端必须携带正确的 Key。 |
| **自定义 Key** | 使用你自己设定的 API Key（保存后生效，可为任意字符串）。 |
| **不校验** | 任何客户端（含不填 Key）都能调用。**请勿在公网暴露**。 |

> 轮换密钥后旧 Key 立即失效。局域网中继使用**独立**的中继 Key，与本机 Key 不通用（见下节）。

---

## Web 控制台功能

| 页面 | 作用 |
| --- | --- |
| **概览** | 模型数量、调用次数、Token 用量、接入地址。 |
| **游乐场** | 在浏览器里直接和模型对话；选模型后自动套用其上下文/输出上限/思考档位；支持系统提示词、流式输出、思考链展开、多轮对话。 |
| **模型清单** | 搜索/筛选全部模型，查看渠道、能力、可用状态，一键复制模型 ID，手动刷新或主动探测。 |
| **白嫖渠道** | 15 条渠道的登录状态与账号池；支持浏览器/设备码/短信登录、启用或删除账号。 |
| **EAC 渠道** | 内置密封凭据解锁的付费车道；点「用 GitHub 授权」登录并 star 仓库后即可使用其模型。 |
| **用量统计** | 按模型汇总输入/输出/思考 Token 与调用次数、失败次数。 |
| **日志** | 每次转发的记录（时间、模型、渠道、结果、延迟、首字延迟、Token、错误信息）；可按模型筛选、只看错误、展开查看请求/响应预览与错误详情。 |
| **服务设置** | 启用/暂停推理、本地转发口开关、地区受限模型展示、断流续写、探测间隔、默认输出上限、出口代理、局域网中继。 |
| **API 接入** | Base URL、API Key、校验方式、调用示例。 |

---

## 局域网共享

想让同一网络中的其它设备（手机、另一台电脑）也能用这些模型：

1. 打开「**服务设置 → 局域网访问**」，勾选「启用局域网转发中继」，可指定端口（`0` = 自动分配），保存。
2. 页面上会显示可拨通的局域网地址，形如 `http://192.168.x.x:<中继端口>/v1`。
3. 中继使用**独立的中继 Key**（在设置页查看/复制/轮换），与第 6 节的本机 Key 不通用。
4. 中继只放行 `/v1/*` 模型接口，且每个请求都要鉴权。

---

## 启动参数

`backend/run.py` 支持以下参数（也可通过 `start.bat` 透传，如 `start.bat --port 18910 --probe`）：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--port` | `18900` | 监听端口；被占用时自动向后寻找可用端口。 |
| `--host` | `127.0.0.1` | 监听地址（默认仅本机）。 |
| `--data-dir` | 项目内 `data/` | 数据目录（凭据、缓存、日志都在这里）。 |
| `--no-refresh` | 关 | 跳过启动时的目录刷新（启动更快，可稍后在控制台手动刷新）。 |
| `--probe` | 关 | 启动后执行一次可用性探测（会对上游发起请求）。 |

---

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `OFM_HOME` | 数据目录（等价于 `--data-dir`）。 |
| `OFM_TLS_VERIFY` | 设为 `0` 可关闭上游 TLS 证书校验（仅在系统证书库导致握手失败时使用）。 |
| `PIP_CACHE_DIR` | pip 缓存目录；`start.bat` 已自动指向项目内 `backend/.pip-cache`。 |

> 若本机设置了 `HTTP_PROXY`/`HTTPS_PROXY`，访问 `127.0.0.1` 时请设置 `NO_PROXY=127.0.0.1`，避免本地请求被代理。

---

## 目录结构

```
python-our-free-model/
├─ start.bat                 # 双击启动（自动建 venv、装依赖、运行服务）
├─ README.md                 # 本文件
├─ PROGRESS.md               # 移植进度与设计记录
├─ .gitignore
├─ backend/
│  ├─ run.py                 # 启动器：选端口、单实例锁、打印 Web UI 地址
│  ├─ requirements.txt       # 依赖清单
│  ├─ .venv/                 # 虚拟环境（自动创建，不入库）
│  └─ ofm/                   # 服务核心
│     ├─ service.py          # FastAPI 应用：路由、鉴权、管理 API、后台循环
│     ├─ runtime.py          # 模型目录 / 可用性刷新 / 出口监视
│     ├─ adapter.py          # 推理主流程（含断流续写、指纹）
│     ├─ forward.py          # OpenAI 兼容端点（chat / responses）
│     ├─ completion.py       # 请求投影、结果折叠、用量换算、日志埋点
│     ├─ catalog.py          # 模型目录构建
│     ├─ probe.py            # 可用性探测、出口 IP 检测
│     ├─ logs.py             # 请求日志（内存环形缓冲 + JSONL 持久化）
│     ├─ eac.py / eac_vault*.py  # EAC 车道（签名、密封凭据解锁、GitHub 授权）
│     ├─ lan_relay.py        # 局域网中继
│     └─ channels/           # 15 条渠道的实现
├─ frontend/                 # 原生 HTML/CSS/JS 控制台（零构建）
│  ├─ index.html
│  ├─ app.js
│  └─ style.css
└─ data/                     # 运行时数据（自动生成，已忽略不入库）
   ├─ settings.json          # 设置（含本机 API Key）
   ├─ catalog.json           # 模型目录缓存
   ├─ availability.json      # 可用性探测结果
   ├─ stats.json             # 用量统计
   ├─ logs.jsonl             # 请求日志
   ├─ service.lock           # 单实例锁
   └─ eac/user.json          # EAC 的 GitHub 授权令牌
```

> `data/` 目录包含**你的凭据与日志**，已在 `.gitignore` 中排除，不会上传到仓库。

---

## 常见问题

**Q：双击 `start.bat` 直接闪退？**
`start.bat` 要求 **CRLF 换行 + 纯 ASCII 内容**；若被工具改坏会解析失败闪退。可先在命令行里运行
`start.bat` 查看具体报错（脚本结尾有 `pause`，正常不会一瞬即逝）。也可改用「命令行手动启动」。

**Q：提示缺依赖？**
首次运行会自动安装。若安装失败，检查网络后重试：
`backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt`。

**Q：端口被占用 / 提示"已经在运行了"？**
默认端口被占用会自动顺延；同一数据目录已有活跃实例时会直接提示并退出（用 `data/service.lock` 判重，
陈旧锁会被自动忽略）。要并行运行请换端口与数据目录。

**Q：网页打开了但界面不更新 / 交互异常？**
控制台静态资源已设 `cache-control: no-store`，强制刷新（`Ctrl+F5`）即可。

**Q：上游请求失败（TLS 握手 / 404）？**
若因系统证书库导致 TLS 失败，可临时设 `OFM_TLS_VERIFY=0`；若因系统代理把 `127.0.0.1` 也走了代理，
请设置 `NO_PROXY=127.0.0.1`。

**Q：Qoder 渠道不可用？**
Qoder 依赖 `wasmtime` 驱动官方 WASM 生成签名，属于可选依赖（`pip install wasmtime` 后重启即可）。

---

## 已知边界

- **账号渠道未逐家真机验证**：各渠道的登录流程与真实回包严格照原版逐行移植，但本人没有一些平台对应账号，
  未做端到端实测；免费车道与 Kilo 已用真实上游验证。
- **Qoder** 的签名算法不可逆向，只能通过 WASM 计算。
- **ZCode / Raccoon / Loomy** 的"积分领取、自动签到"等渠道内附加功能未移植（登录 + 目录 + 推理已具备）。
- 原版面向 DSH 宿主的「自更新 / 热重载 / 公告」等在独立服务中不适用。

---

## 免责声明

本项目仅供学习与个人研究使用，是原版插件的 Python 移植。使用中涉及的第三方服务与免费额度，
请遵守各服务方的条款与授权要求。请勿用于商业用途或对外公开部署。

---

## 致谢

- 原项目：[**dsh-our-free-model**](https://github.com/Ebony-Vinyl/dsh-our-free-model)
- 依赖：FastAPI / Uvicorn / HTTPX / Pydantic / cryptography
