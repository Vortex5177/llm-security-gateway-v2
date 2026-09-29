# 安全评测方法论（Evaluation）

本文说明 M4/M5 评测平台的口径、复现方式与诚实边界。核心叙事：**防护 → 攻击验证 → 发现问题 → 调优规则 → 回归验证**闭环。

## 1. 数据集（evaluation/datasets/）

- **攻击集 64 条**：`attack_prompt_injection_en/cn`、`attack_secret`、`attack_pii`、`attack_obfuscation`，逐条带 `expected_rules`（期望命中的规则 id）、`category`、`lang`、`owasp` 归类。
- **良性集 80 条**：`benign_handcrafted`（V1 真实流量回放 + 手工构造），带 `fp_trap` 陷阱标注（如"校验位错误的身份证不应命中"）。
- **known_gap**：显式声明的检测缺口（如 base64 编码绕过），数量受控（回归测试断言 ≤5），能检出则须转为普通攻击样本。

样本 schema（JSONL，每行一条）：
```json
{"id":"inj-en-001","category":"prompt_injection","lang":"en","text":"...","expected_rules":["injection.ignore_previous_en"]}
{"id":"bn-008","category":"benign","text":"...","fp_trap":"id_card（校验位错误不应命中）"}
```

## 2. 三方对账管线（evaluation/run_eval.py）

**三方对账** = 数据集 ground truth（`expected_rules`）× 网关 `security_events`（按 `X-GW-Request-Id` 关联）× HTTP 响应（状态码 + `X-GW-Security-Action` 头）。

指标定义：
- **detection_rate**：期望可检出的攻击样本中，至少一条期望规则被检出的比例。
- **block_rate**：被实际阻断（400/502 或 `X-GW-Security-Action: block`）的攻击比例。
- **fp_rate**：良性样本中产生**请求侧**安全事件的比例（误报率）。响应侧模型输出异常单列 `output_anomalies`，不计入误报。
- **per_rule_recall**：每条期望规则的命中矩阵。

事件侧别判定：`metadata_json` 含 `message_index` → 请求侧；否则响应侧/流式审计。

复现：
```powershell
# 网关以目标策略启动在 :4101 后
.\.venv\Scripts\python.exe evaluation/run_eval.py --tag round1 [--policy config/security.strict-demo.yaml]
```
报告落 `evaluation/reports/eval-<ts>[-tag].{json,md}`。

## 3. 闭环记录（真实运转两轮）

- **Round1**（默认 audit 策略）：detection 1.0 / fp 0.013 / 3 known_gap。发现 bn-020 误报实为**响应侧**模型输出含隐藏字符 → 管线加 side 分类，响应侧不计入误报。
- **规则调优**：修 5 条规则缺口（phone 数字边界、InvisibleText 加 U+FFFC/U+034F、system_prompt_extract 补 the/中文倒序、jailbreak_keyword 修 CJK `\b` 失效 + 收窄 DAN、ignore_previous_cn 补"无视"）。
- **Round2**：扩展 EN 规则（disregard/bypass/override + 疑问句式），翻转 2 个 known_gap → detection 1.0 / fp 0.0 / 仅剩 1 个 base64 编码绕过（模型层边界）。
- **strict/strict2**（strict-demo 策略）：secret→block 验证，block_rate 0.19（=12 secret/63 可检出，符合仅 block secret 的设计）；修复 strict-demo 配置与主配置的规则漂移。

## 4. 回归测试（tests/security/）

- `test_dataset_regression.py`：引擎级回放全量样本（不依赖运行中的网关）。攻击样本必命中期望规则；良性零命中；known_gap ≤5 且确实检不出（能检出则要求转正）。**保证旧漏洞不复发**。
- 约定：每发现一个绕过样本 → 先入数据集 → 再加规则 → 回归锁定。

## 5. promptfoo CI 式回归

- `evaluation/build_promptfoo_config.py` 从数据集生成 `promptfooconfig.yaml`（代表性子集：每类攻击 1-4 条 + 良性 6 条）。
- `evaluation/pf_parser.js`（`transformResponse`）把 HTTP 状态码与安全响应头提升进 `output`（断言上下文无 `context.response`），断言：strict-demo 下 secret→400+`block`、注入/PII→200、良性→200 且均带 `X-GW-Request-Id`。
- 复现（需设 `GW_ADMIN_KEY`）：
```powershell
.\.venv\Scripts\python.exe evaluation/build_promptfoo_config.py
npx --yes promptfoo eval -c evaluation/promptfooconfig.yaml --no-cache
```
实测 **17/17 通过**。

## 6. garak 子集对账

garak 是重型外部红队工具（torch/transformers），装在独立 `.garak-venv`（gitignored，不污染网关运行时依赖）。

- `evaluation/reconcile_garak.py`：解析 garak `.hitlog.jsonl`，用网关引擎**离线复扫** prompt 文本（确定性，不依赖 request-id 关联），按探针职责域（promptinject/dan/knownbadsignatures/leakreplay/xss = in-scope；encoding/glitch 等 = 模型层）分类 **blocked/detected/passed**，并与运行窗口 `security_events` 交叉核对。
- `evaluation/run_garak_subset.py`：一条命令用 garak `rest` 生成器打网关（运行期注入 admin key，不落库）+ 自动对账。
- `tests/security/test_garak_reconcile.py`：用 garak 真实 hitlog 格式 fixture 验证对账逻辑（5 项，不依赖已安装 garak）。

> garak 各版本探针/生成器命名可能不同；live 运行前用 `.garak-venv\Scripts\python.exe -m garak --list_probes` 校准 `--probes`。

## 7. M5 Rule vs Model 对比（evaluation/model_audit_report.py）

- 离线扫 `request_logs.injected_json` 的 prompt，**重算规则判定** × **CPU 分类器判定**，对比落 `model_audit_results`（不存原文，仅 digest）。
- 正类聚焦 injection（PromptGuard 职责）；PII/secret 属规则专属，不入对比。
- 指标以规则判定为参照算模型 precision/recall/F1 + 一致率 + 延迟对比。
- 分类器：真实 `PromptGuardOnnxClassifier`（可选依赖，懒加载）或 `StubInjectionClassifier`（报告明标非真实模型）。
- 复现：`python evaluation/model_audit_report.py [--limit N] [--model-dir <ONNX 目录>]`。

## 8. 诚实声明与边界

- 所有指标基于**项目受控安全测试集**，不代表生产环境表现（每份报告含 DISCLAIMER）。
- 每份报告含**网关层 vs 模型层边界**分析：known_gap 样本即模型层边界，网关如实记录为缺口，不夸大检出率。
- M5 对比以规则为参照标签，非绝对 ground truth 基准。
