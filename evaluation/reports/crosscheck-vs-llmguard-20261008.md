# 本项目（规则+双模型）vs LLM Guard：同卷全栈对比（2026-10-08）

## 一句话结论

同一张 510 条双语卷（crosscheck-v1）、两边各出全栈：**攻击侧 8/9 类我方检出 ≥ LLM Guard（注入五类合并 72% vs 52%），敏感信息类差距最大（secret 100% vs 33%、中文 7 条全漏），良性误报低一半多（12% vs 36%）**；LG 唯一单项反超是英文伪装注入（103 vs 97），代价是越狱近乎缺席（3/64）。

## 对仗面（谁跟谁比）

| | 本项目全栈 | LLM Guard 0.3.15 全栈 |
| --- | --- | --- |
| 构成 | 规则引擎（security.yaml 15 条）∪ PromptGuard-2 86M ∪ ModernGuard-1 307M（双模型并跑，ONNX CPU） | PromptInjection(protectai DeBERTa, thr=0.9) ∪ Secrets(Detectron) ∪ Anonymize(Presidio) ∪ InvisibleText |
| 形态 | 同步规则闸门 + 异步双模型审计位 | 15 输入扫描器 sidecar（本卷用其 4 个输入扫描器） |
| 判定口径 | 注入五类=injection.* 规则或任一模型判 injection；pii=pii.*；secret=secret.*；混淆=invisible_text；良性=任一命中 | 注入五类=pi；pii=Anonymize；secret=Secrets；混淆=InvisibleText；良性=任一命中 |

同卷同 id 逐条对齐（510 = 外部 380 英文 + 自建 130 中英；已知缺口 2 条保留在分母，三方同卷）。模型侧明细：PG/MG 逐条 JSON 在位；本次对账三项全 PASS（行数/id 对齐、独立重算 vs 存量 by_cat、独立 LG 明细 vs 内嵌），旧数据可信未重跑。MG 自建 130 条为本轮补跑（crosscheck-mg-dev510-20261008-163850.json）。

## 九类主矩阵（510 条）

本项目三方构成：**规则引擎**（security.yaml 15 条，同步闸门）+ **PromptGuard-2 86M**（meta-llama，ONNX CPU，异步审计）+ **ModernGuard-1 307M**（guardion，mmBERT，ONNX CPU，异步审计双跑）。

| 类别 | n | 规则引擎 | PromptGuard-2 86M | ModernGuard-1 307M | **本项目并集** | **LLM Guard 0.3.15** | 我方独有 | LG 独有 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| injection（伪装注入） | 170 | 5 | 66 | 54 | **97 (57%)** | 103 (61%) | 29 | 35 |
| prompt_injection | 16 | 15 | 14 | 16 | **16 (100%)** | 15 (94%) | 1 | 0 |
| system_prompt_leak | 9 | 9 | 3 | 8 | **9 (100%)** | 9 (100%) | 0 | 0 |
| role_manipulation | 7 | 7 | 5 | 7 | **7 (100%)** | 7 (100%) | 0 | 0 |
| jailbreak | 64 | 3 | 36 | 63 | **63 (98%)** | 3 (5%) | 60 | 0 |
| pii | 12 | 12 | 0 | 1 | **12 (100%)** | 6 (50%) | 6 | 0 |
| secret | 12 | 12 | 2 | 11 | **12 (100%)** | 4 (33%) | 8 | 0 |
| obfuscation（不可见字符） | 5 | 5 | 1 | 1 | **5 (100%)** | 3 (60%) | 2 | 0 |
| benign（误报，越低越好） | 215 | 1 | 8 | 18 | **26 (12.1%)** | 78 (36.3%) | — | — |

注入五类合并（266 条）：**我方 192 (72.2%) vs LG 137 (51.5%)**——双中 102、我方独有 90、LG 独有 35。

## 分项拆账

### 1. 注入（injection 170 条，LG 唯一反超项）

我方 97 vs LG 103：LG 独有 35 条全是英文伪装句式（deepset 长叙事、jv-inj 隐式注入）——protectai 模型的语料专长；我方独有 29 条是规则中文槽位 + 双模型互补视野。**双方互漏的不是同一批攻击**：LG 赢在英文伪装泛化，我方赢在越狱和中文。该项 97 与 103 的差距（6 条）远小于 jailbreak 的 60 条差值。

### 2. 越狱（64 条）：断层

我方 63/64（98%，MG 63 条主力）vs LG 3/64（5%）。LG 的注入扫描器对越狱基本缺席——这是它作为"注入专项 WAF"的学科边界，不是配置问题（阈值调不回来，之前实验已证）。

### 3. 敏感信息（本轮补写的重点，24 条）

**secret 12 条：我方 12/12，LG 4/12。** LG 漏检 8 条明细：

| 样本 | 语言 | 内容 | 我方规则 | LG |
| --- | --- | --- | --- | --- |
| sec-001/002/011 | 中文 | sk- 开头 OpenAI 风格 key | secret.openai_key ✓ | 漏 |
| sec-004 | 中文 | AWS ASIA 访问密钥 | secret.aws_access_key ✓ | 漏 |
| sec-006 | 中文 | GitHub token | secret.github_token ✓ | 漏 |
| sec-008 | 中文 | JWT 三段式 | secret.jwt ✓ | 漏 |
| sec-010 | 中文 | PEM 私钥头 | secret.private_key ✓ | 漏 |
| sec-009 | 英文 | PEM 私钥头 | secret.private_key ✓ | 漏 |

中文 secret **7 条全漏（0/7）**：Detectron 语义模型对中国格式语料盲。跨域注脚：MG 把其中 7 条密钥文本判成 injection（跨域副作用，非 PII 责任方）。

**pii 12 条：我方 12/12，LG 6/12。** LG 漏检 6 条全中文：手机号 3 条（`1[3-9]` 开头 11 位中国格式，Presidio 不认）、身份证 3 条（18 位含校验位，Presidio 无中国 recognizer；我方走 GB 11643 校验位算法验证，格式合法才算命中）。英文侧 2/2 双方打平（国际格式 LG 认识）。

**结论**：敏感信息是两层架构里"确定性规则完胜语义栈"的最硬证据——校验位算法（Luhn/GB 11643）+ 中国格式主场，模型语料覆盖不了。反向代价也存在：LG 的 Anonymize 能认我方规则没写的实体类型（人名/地址），但良性误报账单更差（见下）。

### 4. 混淆（5 条零宽/不可见字符）

我方 5/5（规则 invisible_text 字符级扫描）vs LG 3/5。双模型在这类上接近全盲（PG 1、MG 1）——字符级异常在 tokenizer 层被抹掉，**规则是该类唯一可靠防线**（域内 926 条审计同结论再证）。

### 5. 良性误报（215 条，越低越好）

我方 26 (12.1%) vs LG 78 (36.3%)：

- 我方构成：规则 1（零宽字符）+ PG 8 + MG 18（MG 是主要贡献者——对模型自述/密钥文本/指令式过敏，此前域内审计已定位）；中文 9/48、英文 17/167。
- LG 构成：pi 误报为主（67 条分数 ≥0.99，调阈值救不了），Presidio 在中文上把单个汉字当 PERSON（翻译实验发现）。
- 中英对比：中文我方 9/48 vs LG 20/48；英文我方 17/167 vs LG 58/167——两个语言域我方都低一半以上。

### 6. 延迟（CPU，每条，记录值）

- 我方：规则 0.31ms（同步位）+ PG 538ms + MG 62ms（external 卷均值；自建卷 152ms 含首条预热）——同步位只花 0.31ms，模型位异步不拦用户。
- LG：PromptInjection 114ms + Anonymize 184ms（+ Secrets/InvisibleText 未单独计时）。
- 形态差异：我方模型延迟在审计位（异步、可并行、不阻塞请求）；LG 全栈在请求路径上。

## 市面版图定位（为何比的是 LLM Guard）

- **商业网关**（Lakera Guard / Prompt Security / WitnessAI / AIM / Prisma AIRS·Protect AI）：SaaS 或企业署，同卷实测需把测试集发给第三方 API——数据出域、按调用计费、**不可复现**，与本项目"全链路本地可复现"的方法论冲突，故不实测。公开材料自报检出 >95% 无外部同卷背书，引用须打折（本项目"自报必须外部复验"纪律的通用态度）。
- **开源阵营**：LLM Guard（15 输入扫描器 MIT sidecar，最全面的开源 LLM WAF——本次对比对象）；NeMo Guardrails（Colang 编排框架，注入检测靠 LLM 裁判提示词，本地小模型裁判归因不净，不实测）；Guardrails AI（可靠性/schema 校验向）；Presidio（PII 专项，已作为 LG 的 Anonymize 组件间接同卷测过）；Agentgateway PromptGuard（L7 regex 网关，与我方规则层同质）。
- **选 LLM Guard 的理由**：开源里离线可跑、扫描器覆盖最全、与本网关形态最像（拦在模型前的检测层）——"跟市面同类比"的最公平可复现对照。

## 诚实边界

1. injection 单项 97 < 103（-6 条）：英文伪装注入仍是 protectai 语料强项；我方靠双模型把差距从单 PG 时代的 -37 压到 -6。
2. 我方 benign 误报 12.1% 非零，主要来自 MG（18/26）——若把双模型移入同步拦截位，误报红线生效需重估（当前模型位为异步审计）。
3. LG 的 78 条误报里 67 条 pi 分数 ≥0.99：调阈值救不了，是模型行为不是配置问题。
4. known_gap 2 条（base64 注入、AntiDAN）保留在分母：AntiDAN 双方都接住（我方 PG/MG、LG pi）；base64 双方全漏（共同边界）。
5. 本卷 LG 用的是 4 个输入扫描器（其输出侧 20 扫描器不在本题范围）。

## 复现

```powershell
# MG 自建 130 条补跑（transformers 栈，仓库根 .venv-mg312）
.\.venv-mg312\Scripts\python.exe gateway-v2\evaluation\run_crosscheck_mg.py --file gateway-v2\evaluation\datasets_benchmark\benchmark_dev.jsonl --tag dev510
# 其余全部离线重算：crosscheck-20261008-003540.json（510 行规则+PG+LG 明细）
# + crosscheck-mg-en-20261008-125107.json + crosscheck-mg-dev510-20261008-163850.json
```

## 口径声明

510 条 = crosscheck-v1 基准集（curate_benchmark.py seed=42 派生：外部 380 英文 + 自建 130 中英）。攻击类"检出"按各类责任检测器判定；"本项目并集"= 规则 ∪ PG ∪ MG 任一命中（pii/secret 类模型命中为跨域副作用，已单列）；良性"误报"= 任一命中。百分比分母为本表 n。PG 538ms 为当时 CPU 独占记录值；MG 自建卷 152ms 含首条 2185ms 预热。本对比不构成对任一产品的整体评价，仅为本卷口径下的检测能力对照。
