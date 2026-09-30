# llm-gateway (V2)

> Enterprise LLM Security Gateway · OpenAI-Compatible · 单用户自托管

V2 = V1 通用 LLM 网关 + 企业 AI 安全能力，闭环叙事：防护 → 攻击验证 → 规则调优 → 回归测试。

**接入安全**

- **API Key 鉴权**：`server.auth.enabled: true` 时 `/v1/*` 需 `Authorization: Bearer gw_...`；密钥仅存 SHA-256 哈希（明文仅创建时返回一次）；首次启动自动签发引导 admin key（控制台打印 + `data/bootstrap_admin_key.txt`，不入库）
- **RBAC（从简）**：admin / developer / user 三角色；管理端点（`/api/keys`、`/api/providers*`、`/api/local-vllm*`）仅 admin；每 key 可配 `allowed_models` 模型白名单（别名解析前对客户端请求名生效，越权 403 + 事件）
- **限流**：内存令牌桶 per key（`rpm_limit`/`burst` 可配，缺省不限），超限 429 + 事件
- **SSRF 防护**：看板 API 动态添加的 provider 一律校验 base_url——仅 http/https，拒绝回环/内网/链路本地（含云元数据 169.254.169.254）与 `.local/.internal` 主机名；`security.ssrf.allow_hosts` 显式豁免（支持 `host` 或 `host:port`）；配置文件中的 provider 视为可信不校验（不做 DNS 解析，见已知边界）
- **统一安全事件**：鉴权失败 / 限流 / 模型越权 / SSRF 拦截 / key 与 provider 管理操作全部落 `security_events` 表（event_type/severity/action/source_ip/request_id/...，事件不含密钥与敏感原文；防篡改哈希链见「安全运营」一节）
- 新增端点：`POST /api/keys`（创建，明文仅返回一次）、`GET /api/keys`、`POST /api/keys/{name}/disable`；所有响应带 `X-GW-Request-Id`

**内容安全**

- **策略引擎外置**：`config/security.yaml` 定义规则（id/检测器/pattern/severity/action/owasp），动作三档 `block / redact / audit`；默认全 audit 观察误报，`config/security.strict-demo.yaml` 为演示用收紧配置（secret→block、PII→redact）；同文本多命中按 block > redact > audit 裁决
- **请求护栏**：扫描全部 message 文本（含 content parts）；block → 400 `content_policy_error`；redact → 占位符替换（`[REDACTED_PII_PHONE_1]`，llm-guard 模式保句子结构）后放行；audit → 仅记事件
- **响应护栏（非流式）**：block → 502；redact → 改写 choices 内容；**流式响应**：滑窗增量扫描（解决跨 chunk 命中）audit-only，流量逐字节不变、命中只记事件
- **检测器**：regex / 身份证（GB 11643 校验位）/ 银行卡（Luhn）/ InvisibleText（零宽字符 + Tags 区块 ASCII smuggling）；默认规则覆盖手机号/身份证/银行卡/邮箱、OpenAI/AWS/GitHub key、JWT、PEM 私钥、指令覆盖（中英）/系统提示提取/角色操纵/越狱关键词
- **事件纪律**：pii/secret 命中只记 rule_id 与 span、绝不记原文；injection 命中记截断预览；每条规则带 OWASP LLM Top 10 映射
- 良性基线：默认规则集对 50 条 V1 真实流量抽样误报率 0%（`evaluation/export_benign.py` 可复跑）

**安全运营**

- **防篡改审计链**：`security_events` 每条记录 `hash = sha256(prev_hash + canonical_json)`，全局锁串行写入保证链序；`verify_audit_chain()`（CLI `python -m app.audit verify` 或 `GET /api/security/verify`）可定位内容篡改与删行；已知边界：链尾删除需外部 checkpoint（future work）
- **安全运营 API**：`GET /api/security/events`（severity/type/rule_id/days 过滤）、`GET /api/security/summary`（总量/分布/Top 规则/最近事件）、`GET /api/security/verify`（均仅 admin 或本机看板）
- **看板 Security 页**：安全事件/高危/阻断/脱敏卡片、类型与级别分布图、Top 规则、最近事件表、一键链校验；页首 API Key 输入（localStorage）供管理接口调用

**红队评测**

- **数据集**：`evaluation/datasets/` 攻击集 65 条（指令覆盖中英 / 系统提示提取 / 角色操纵 / 越狱关键词 / 隐藏字符 / 语义越狱 / PII / Secret，逐条带 `expected_rules` 标签与 OWASP 归类）+ 良性集 80 条（V1 真实流量回放 50 + 手工陷阱 30，含 `fp_trap` 标注）；`known_gap` 2 条显式声明检测缺口（base64 编码绕过与 garak AntiDAN 语义越狱，属模型层）
- **对账评测管线**：`evaluation/run_eval.py` 打真实网关 → 按 `X-GW-Request-Id` 关联 `security_events` → 与数据集 ground truth **三方对账**，输出检出率/阻断率/误报率/按规则召回矩阵（JSON + Markdown 落 `evaluation/reports/`）；请求侧误报与响应侧模型输出异常分列，不夸大指标
- **闭环验证**（默认 audit 策略）：Round1 检出 1.0 / 误报 0.013 → 定位规则缺口（phone 数字边界、隐藏字符漏 U+FFFC/CGJ、系统提示提取漏 the/中文倒序、越狱关键词 CJK `\b` 失效）→ 扩展规则 → Round2 检出 1.0 / 误报 0.0；strict-demo 策略下 secret→block，阻断率 0.19（=12 secret/63 可检出，符合仅 block secret 的设计）
- **回归测试**：`tests/security/test_dataset_regression.py` 引擎级回放全量样本（攻击必命中期望规则、良性零命中、known_gap 受控 ≤5 且确实检不出），保证旧漏洞不复发
- **promptfoo CI 式回归**：`evaluation/build_promptfoo_config.py` 从数据集生成 `promptfooconfig.yaml`（代表性子集），经 `evaluation/pf_parser.js`（transformResponse 提升 HTTP 状态码与安全头进 output）断言 strict-demo 下 secret→400+block、注入/PII→200、良性→200 且均带 `X-GW-Request-Id`；实测 **17/17 通过**
- **garak 子集对账**：garak 为重型外部工具，装在独立 `.garak-venv`（不污染网关依赖）；`evaluation/reconcile_garak.py` 解析 garak `.hitlog.jsonl`，用网关引擎离线复扫 prompt 文本，按探针职责域分类 blocked/detected/passed 并与运行窗口事件交叉核对（5 项自测通过）；`evaluation/run_garak_subset.py` 一条命令跑 rest 生成器打网关 + 自动对账
- 所有报告含**诚实声明**（受控测试集，非生产表现）与**网关层 vs 模型层边界**分析

> 复跑评测：网关以目标策略启动后 `python evaluation/run_eval.py --tag <name>`；promptfoo：`python evaluation/build_promptfoo_config.py` 后 `npx promptfoo eval -c evaluation/promptfooconfig.yaml`（需设 `GW_ADMIN_KEY`）。

**模型辅助审计**

- **CPU 分类器异步审计**：`app/security/model_audit.py` 离线批处理扫 `request_logs`（不进请求路径，不扰动稳定服务），对每条 prompt 重算规则判定并跑模型分类，对比落 `model_audit_results` 表（不存 prompt 原文，仅 sha256 digest）
- **分类器可插拔**：真实 `PromptGuardOnnxClassifier`（PromptGuard 2 86M ONNX，onnxruntime/transformers 为**可选依赖**，懒加载，缺失时显式报错不静默降级）+ `StubInjectionClassifier`（确定性关键词桩，无模型时演示管线，报告明标非真实模型）；遵守“不引重型依赖”：模型依赖不入网关运行时 venv
- **Rule vs Model 对比报告**：`evaluation/model_audit_report.py` 以规则判定为参照算模型 injection 检出的 precision/recall/F1 + 一致率 + 延迟对比（JSON+MD 落盘）；正类聚焦 injection（PromptGuard 职责），PII/secret 属规则专属不入对比
- **结论**：确定性规则适合有固定格式/可校验的 PII/Secret（微秒级、可解释、可脱敏）；语义模型适合改写/编码绕过/新颖注入（补召回）；分歧样本正是规则调优的闭环输入

> 复跑：`python evaluation/model_audit_report.py [--limit N] [--model-dir <PromptGuard ONNX 目录>]`（缺省用 Stub）。

**V1 基础能力（继承）**

自托管、OpenAI 协议兼容的薄网关：把本地 vLLM（WSL2）与云端 API（DeepSeek / DashScope）统一到一个入口，提供模型别名解析、服务端回退链、硬顶参数注入、本地模型启停管理与全链路可观测性。

## 架构

```
┌──────────────────────── 客户端 ────────────────────────┐
│   Chatbox 桌面版 / Python 脚本 / LangChain / 其他本地项目   │
└──────────────┬─────────────────────────────────────────┘
               │  OpenAI 协议: POST /v1/chat/completions (JSON / SSE)
               ▼
┌──────────────────── 网关 :4101 ─────────────────────────┐
│   别名解析 → 硬顶注入 → 回退链 → 上游转发                    │
│   请求落库(SQLite) · 指标采样(NVML + vLLM /metrics)         │
│   零构建静态看板 /  ·  聚合 API /api/stats                  │
└──────┬──────────────────────────────────┬───────────────┘
       ▼                                  ▼
 本地 vLLM :8200 (WSL2)            云端 API (DeepSeek / DashScope)
```

设计原则：**客户端只说"要什么"（模型 + 问题 + 可选 tag），网关决定"给谁做、怎么做、坏了换谁"**——协议适配、路由、护栏、记账全部收敛在网关层。

## 特性

- **OpenAI 兼容**：`POST /v1/chat/completions`（流式 + 非流式）、`GET /v1/models`；任何 OpenAI 兼容客户端改 base_url 即可接入
- **模型别名与切换**：`gateway.yaml` 的 `aliases` 把逻辑名映射到真实模型；切换本地/云只改一行，客户端零改动
- **服务端回退链**：`primary → fallbacks`，键支持 `模型@tag` 精确覆盖；客户端无感，响应头（`X-GW-Attempts` 等）与落库字段可观测
- **硬顶参数注入**：按 tag 覆盖（如 `max_tokens`、`repetition_penalty`），防弱模型失控/重复生成；客户端原值仅记审计
- **流式细节**：TTFT 度量、`stream_options.include_usage` 自动注入、客户端断连时 `asyncio.shield` 兜底清理（断连也保证落库）
- **可观测性**：NVML GPU 采样 + vLLM `/metrics` 引擎指标 → SQLite → 聚合 API → 零依赖 Chart.js 看板（请求/tokens/延迟/TTFT/生成速度(tokens/s)/GPU 曲线、tag 分组、模型与 Provider 面板）
- **健康检查**：`GET /health` 报告各 provider 可达性
- **Provider 管理**：看板直接填密钥、手动添加 Provider（预设 Moonshot / 智谱 / SiliconFlow + 自定义）；新增后热生效，`provider/模型名` 前缀路由直通上游，无需登记模型映射
- **本地模型启停/切换**：看板查看 WSL2 vLLM 运行态并一键启动 / 停止 / 切换候选模型（进程与状态文件交叉校验）；控制接口仅限本机严格同源调用

## 快速开始

环境要求：Python ≥ 3.11；Windows 主机；WSL2（可选，本地模型需要）

```powershell
# 1. 环境
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. 配置：按需编辑 gateway.yaml；云端密钥放 .env（模板见 .env.example），也可在启动后于看板填密钥/添加 Provider

# 3. 本地模型（可选）：配置 gateway.yaml 的 local_vllm 段后可在看板一键启停/切换，或直接 WSL 内启动（端口 8200）
wsl -d Ubuntu-24.04 -- /opt/scripts/start-vllm.sh

# 4. 启动网关
.\start.ps1

# 5. 验证
.\.venv\Scripts\python.exe smoke_test.py     # 端到端冒烟
# 浏览器打开 http://127.0.0.1:4101/ 查看监控看板
```

## 端点

| 端点                               | 说明                                                             |
| -------------------------------- | -------------------------------------------------------------- |
| `POST /v1/chat/completions`      | 聊天补全（流式/非流式），OpenAI 兼容                                         |
| `GET /v1/models`                 | 模型与别名清单                                                        |
| `GET /health`                    | 存活 + 各 provider 可达性                                            |
| `GET /api/stats?days=N&tag=X`    | 聚合统计（总量 / tag 分组 / 时间序列 / GPU / 引擎 / 最近请求）                     |
| `GET /api/models`                | 模型目录（名称 / 本地或云 / 别名 / 回退链）+ provider 接入状态（密钥来源 / 连通性）          |
| `GET /api/local-vllm`            | 本地 vLLM 状态（运行态 / 当前模型 / 候选清单；仅限本机）                             |
| `POST /api/local-vllm/start`     | 启动本地 vLLM（body 可选 `{"model": "候选名"}`；仅限本机看板）                   |
| `POST /api/local-vllm/switch`    | 切换本地 vLLM 候选模型（仅限本机看板）                                         |
| `POST /api/local-vllm/stop`      | 停止本地 vLLM（仅限本机看板）                                              |
| `POST /api/providers`            | 添加 Provider（预设或自定义 base_url）：写用户 overlay + `.env` 并热生效（仅限本机调用） |
| `POST /api/providers/{name}/key` | 保存 provider 密钥：写 `.env` 并即时生效（仅限本机调用；保存后立即复探测并返回连通性）           |
| `GET /`                          | 静态监控看板                                                         |

## 配置说明（gateway.yaml）

| 段            | 作用                                                                                           |
| ------------ | -------------------------------------------------------------------------------------------- |
| `server`     | 监听地址、上游超时、鉴权开关（默认关闭，仅监听 127.0.0.1）                                                           |
| `providers`  | 上游服务：base_url + 密钥（明文或 `*_env` 环境变量引用）+ metrics_url + 可选 `type`（local/cloud，缺省按 base_url 推断） |
| `models`     | 客户端可见名 → provider + 上游真实名                                                                    |
| `aliases`    | 逻辑别名（如 `default`），切换本地/云只改这一行                                                                |
| `fallbacks`  | 服务端回退链；键支持 `模型@tag` 精确覆盖                                                                     |
| `injection`  | 硬顶注入表：tag 精确匹配 + `default` 兜底；`extra` 展开到请求体顶级                                               |
| `local_vllm` | 本地 vLLM 管理：启用开关、WSL 发行版、启动脚本、候选模型路径（候选名 = 目录名小写，需有对应 models 映射）                              |
| `sampling`   | 指标采样间隔与 GPU 来源（auto / nvml / wsl）                                                            |

看板添加的 Provider 写入 `data/gateway.user.yaml`（overlay，与 gateway.yaml 合并加载；同名以 gateway.yaml 为准），密钥写入 `.env`。

## 数据与可观测性

每次请求落库 `data/gateway.db` 的 `request_logs` 表（该目录不入库）：请求/解析模型、provider、是否流式、prompt/completion tokens、延迟、TTFT、输出速率（tokens/s）、状态、HTTP 状态码、attempts、回退标记、错误信息、注入快照、tag、时间戳。看板与 `/api/stats` 均读自此表。

## 测试与验收

```powershell
.\.venv\Scripts\python.exe -m pytest                       # 858 个单元/安全测试（上游用 MockTransport stub；含数据集回归 144 + garak 对账 7）
.\.venv\Scripts\python.exe smoke_test.py                   # 38 项端到端检查（真调本地 vLLM）
.\.venv\Scripts\python.exe smoke_test.py --fallback-demo   # 9 项回退链检查（先以 gateway.fallback_demo.yaml 在 :4101 启动演示网关）

# 安全评测——需网关已以目标策略启动在 :4101
.\.venv\Scripts\python.exe evaluation/run_eval.py --tag round1              # 三方对账评测，报告落 evaluation/reports/
.\.venv\Scripts\python.exe evaluation/build_promptfoo_config.py            # 生成 promptfoo 配置
npx --yes promptfoo eval -c evaluation/promptfooconfig.yaml                # CI 式回归（需设 GW_ADMIN_KEY）
.\.venv\Scripts\python.exe evaluation/reconcile_garak.py --hitlog <path>   # garak hitlog 三方对账
.\.venv\Scripts\python.exe -m app.audit verify                             # 审计哈希链校验
```

## 目录结构

```
app/            网关主体（config / registry / routing / proxy / streaming / sampler / stats / vllm_service + routes）；wsl_vllm_control.py 为 WSL 侧启停助手
app/security/   安全引擎（ssrf / detectors / policy / engine）；app/auth.py / ratelimit.py / audit.py 为鉴权/限流/审计链
config/         security.yaml（默认全 audit）+ security.strict-demo.yaml（演示收紧）
evaluation/     数据集 / 对账评测管线 run_eval.py / promptfoo 配置生成 / garak 对账 / 报告
static/         零构建看板（index.html + dashboard.js + vendored Chart.js）
tests/          pytest 单元测试；tests/security/ 为安全回归（数据集回放 + garak 对账）
gateway.yaml    主配置；gateway.fallback_demo.yaml 为回退链演示配置（配合 smoke_test --fallback-demo）
smoke_test.py   端到端冒烟脚本
start.ps1       一键启动
```

## 已知边界（v1）

- 仅实现 chat completions；无 embeddings / completions 等端点
- 本地模型管理依赖 Windows + WSL2 环境
- 单用户本地工具：鉴权默认关闭、仅监听 127.0.0.1（网页版浏览器客户端受浏览器安全限制无法访问 localhost，需桌面客户端）
- 配置驱动的规则路由（别名 / tag），无 ML 智能路由
- 无容器化、无压测结论
