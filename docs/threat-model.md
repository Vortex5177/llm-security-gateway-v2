# 威胁模型（Threat Model）

本项目定位 **Enterprise LLM Security Gateway & Security Evaluation Platform**：在 OpenAI 兼容薄网关上叠加纵深防御，并以红队评测验证。本文按 OWASP LLM Top 10（2025）映射网关控制项，并明确**网关层可防 vs 模型层威胁**边界。

## 资产与信任边界

- **受保护资产**：上游 provider 密钥（DeepSeek/DashScope）、本地 vLLM 算力、用户 prompt/completion 中的 PII 与 Secret、审计日志完整性。
- **信任边界**：客户端 →（API Key 鉴权）→ 网关安全护栏 →（SSRF 校验）→ 上游 provider / 本地 vLLM。网关默认不信任客户端输入，也不完全信任模型输出（响应护栏）。
- **数据平面 vs 管理平面**：`/v1/*` 为数据平面（任意有效 key）；`/api/*` 管理平面（仅 admin 或本机看板 Origin）。

## OWASP LLM Top 10 → 网关控制映射

| OWASP | 威胁 | 网关控制（里程碑） | 层 |
| --- | --- | --- | --- |
| LLM01 Prompt Injection | 指令覆盖/角色操纵/系统提示提取/隐藏字符注入 | 请求护栏规则引擎（`injection.*`）、InvisibleText 检测（Cf/Tags/U+FFFC/U+034F）、流式滑窗 audit（M2） | 网关（已知模式）+ 模型（语义绕过） |
| LLM02 Sensitive Info Disclosure | PII/Secret 泄露给模型或经响应外泄 | 检测器（身份证 GB11643 校验位/银行卡 Luhn/正则）、占位符脱敏 `[REDACTED_*]`、事件不记原文只记 span、响应护栏（M2） | 网关 |
| LLM02（凭据） | 上游密钥泄露/越权调用 | API Key SHA-256 哈希存储、明文仅创建返回一次、RBAC-lite（role+allowed_models）、密钥值绝不入日志/响应（M1） | 网关 |
| LLM04 Data/Model Poisoning | （本项目不训练，弱相关） | 不适用；审计链保证事件不可篡改（M3） | — |
| LLM05 Improper Output Handling | 模型输出含恶意内容/隐藏字符 | 响应护栏（非流式 block/redact）、流式 audit-only 检出（M2） | 网关（检出）+ 模型（生成） |
| LLM06 Excessive Agency | 越权访问管理端点/模型 | 管理端点 admin 守卫、模型白名单在别名解析前校验（M1） | 网关 |
| LLM07 System Prompt Leakage | 诱导泄露系统提示 | `injection.system_prompt_extract`（中英、正倒序、疑问句式）（M2/M4） | 网关（已知模式）+ 模型 |
| LLM08 Vector/Embedding Weakness | 不适用（无 RAG/embeddings 端点） | — | — |
| LLM09 Misinformation | 模型幻觉/错误信息 | 不在网关职责；评测报告边界声明（M4） | 模型 |
| LLM10 Unbounded Consumption | 滥用/DoS/资源耗尽 | per-key 令牌桶限流（RPM/burst，时钟可注入）、硬顶参数注入（max_tokens 等）（M1） | 网关 |
| SSRF（云元数据） | 看板动态添加 provider 指向内网/元数据 | `security/ssrf.py`：拒回环/RFC1918/link-local/169.254.169.254，allow_hosts 豁免（M1） | 网关 |
| 审计完整性 | 日志被篡改/删行以掩盖攻击 | `security_events` 哈希链 `sha256(prev_hash+canonical_json)`、asyncio.Lock 串行、`verify_chain` 定位篡改（M3） | 网关 |

## 网关层可防 vs 模型层威胁（诚实边界）

- **网关层可防（规则可判定，确定性）**：PII/Secret 泄露（有固定格式且可校验）、已知注入模式、隐藏字符注入、鉴权/限流/越权、SSRF、审计完整性。特点：微秒级延迟、可解释、可脱敏改写。
- **需模型层防御（语义/多轮/编码绕过）**：base64/翻译类编码绕过、语义改写注入、多轮渐进越狱（Crescendo 类）、下游模型自身服从性、幻觉。网关对这些**如实记录为缺口（known_gap）**，不夸大检出率。
- **M5 补位**：CPU 小分类器（PromptGuard 2 86M）异步补检语义类注入，扩大召回；规则做第一道确定性防线，模型做异步 audit，二者分歧样本反哺规则调优（闭环）。

## 攻击面收敛决策（对齐最终方案）

- 删 JWT，仅 API Key（SHA-256 哈希）——降低复杂度与密钥管理面。
- RBAC 从简（role + allowed_models 两字段）——够用即可，避免过度设计。
- SSRF 仅校验看板 API 动态添加的 provider（配置文件里的 provider 视为可信，豁免）。
- 流式响应护栏 audit-only——不扰动 V1 精密流路径，失败模式无害。
- 哈希链只链 `security_events`——聚焦安全审计完整性，不牵连高频 request_logs。

## 失败模式与降级

- 策略文件缺失 → 引擎不启用，退化为 V1 行为（可用性优先）。
- 限流/鉴权依赖内存态 → 单实例部署假设；多实例需外部共享存储（future work）。
- 哈希链链尾删除 → 需外部 checkpoint 锚定（future work）。
- 模型分类器依赖缺失 → 显式报错，不静默降级；离线审计可回退 Stub（报告明标）。
