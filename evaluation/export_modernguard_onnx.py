# -*- coding: utf-8 -*-
r"""ModernGuard-1 导出 ONNX + 双栈一致性校验（跑在仓库根 .venv-mg312，一次性导出工具）。

步骤：
1. 从 HF 缓存加载 guardion/ModernGuard-1（eager attention，可导出形态）；
2. torch.onnx.export 动态 seq 轴（先试 legacy，失败转 dynamo），opset 18；
3. tokenizer/config 落位 data/models/modernguard1-307m/；
4. 一致性校验：中英 benchmark 各取 15 条（攻击+良性混合），
   torch softmax[PROMPT_INJECTION] vs ONNX softmax[1]，报最大绝对差，超差退出非零。

用法（仓库根，模型经 hf-mirror 缓存过）：
    .\.venv-mg312\Scripts\python.exe gateway-v2\evaluation\export_modernguard_onnx.py

产物：gateway-v2/data/models/modernguard1-307m/{model.onnx, tokenizer*, config.json}
（生产侧由 app/security/model_audit.py 的 ModernGuardOnnxClassifier 消费，
网关 venv 无 torch，仅需 onnxruntime + transformers tokenizer。）

导出后已在网关 venv 做过外部全量对齐（2026-10-08）：EN 510 / ZH 380，
与 transformers 版零二值翻转、外部 380 条分类数字逐类一致（详见 adoption 报告）。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
sys.stdout.reconfigure(encoding="utf-8")

import numpy as np  # noqa: E402
import onnxruntime as ort  # noqa: E402
import torch  # noqa: E402
from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: E402

MODEL_ID = "guardion/ModernGuard-1"
OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "models" / "modernguard1-307m"
EN_JSONL = Path(__file__).resolve().parent / "datasets_benchmark" / "benchmark_external_en.jsonl"
ZH_JSONL = Path(__file__).resolve().parent / "datasets_benchmark_zh" / "benchmark_external_zh.jsonl"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, attn_implementation="eager")
    model.eval()
    print(f"加载完成 id2label={model.config.id2label}", flush=True)

    # ---- 导出
    enc = tokenizer("connect your database", return_tensors="pt")
    input_names = list(enc.keys())
    args = tuple(enc[k] for k in input_names)
    onnx_path = OUT_DIR / "model.onnx"
    exported = False
    # opset 18：dynamo 导出器的 Split 节点带 num_outputs 属性（opset 18 语法），
    # 降级到 17 会留属性成非法图，必须导出为 18（onnxruntime 1.30 支持）
    try:
        torch.onnx.export(
            model,
            args,
            str(onnx_path),
            input_names=input_names,
            output_names=["logits"],
            dynamic_axes={k: {0: "batch", 1: "seq"} for k in input_names} | {"logits": {0: "batch"}},
            opset_version=18,
        )
        exported = True
        print("legacy 导出成功", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"legacy 导出失败：{exc}", flush=True)
    if not exported:
        torch.onnx.export(
            model,
            args,
            str(onnx_path),
            input_names=input_names,
            output_names=["logits"],
            dynamic_axes={k: {0: "batch", 1: "seq"} for k in input_names} | {"logits": {0: "batch"}},
            opset_version=18,
            dynamo=True,
        )
        print("dynamo 导出成功", flush=True)

    tokenizer.save_pretrained(OUT_DIR)
    model.config.save_pretrained(OUT_DIR)
    print(f"tokenizer/config 落位 {OUT_DIR}", flush=True)

    # ---- 一致性校验（torch vs onnx）
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    sess_inputs = [i.name for i in session.get_inputs()]
    print(f"ONNX 输入节点：{sess_inputs}", flush=True)

    samples = []
    for p, n in ((EN_JSONL, 15), (ZH_JSONL, 15)):
        rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
        atk = [r for r in rows if r["category"] == "injection"][:8]
        jb = [r for r in rows if r["category"] == "jailbreak"][:4]
        ben = [r for r in rows if r["category"] == "benign"][:3]
        samples += [r["text"] for r in atk + jb + ben]

    max_diff = 0.0
    n_flip = 0
    for text in samples:
        enc = tokenizer(text, return_tensors="pt", truncation=True, max_length=2048)
        input_ids = enc["input_ids"]
        attn = enc["attention_mask"]
        with torch.no_grad():
            torch_probs = torch.softmax(model(input_ids=input_ids, attention_mask=attn).logits, dim=-1)[0]
        ort_inputs = {"input_ids": input_ids.numpy(), "attention_mask": attn.numpy()}
        if "token_type_ids" in sess_inputs:
            ort_inputs["token_type_ids"] = enc.get("token_type_ids", attn * 0).numpy()
        ort_logits = session.run(None, ort_inputs)[0][0]
        ort_probs = np.exp(ort_logits - ort_logits.max())
        ort_probs = ort_probs / ort_probs.sum()
        t = float(torch_probs[1])
        o = float(ort_probs[1])
        diff = abs(t - o)
        max_diff = max(max_diff, diff)
        if (t >= 0.5) != (o >= 0.5):
            n_flip += 1
            print(f"  [FLIP] torch={t:.4f} onnx={o:.4f} text={text[:40]!r}", flush=True)

    print(f"\n一致性校验：{len(samples)} 条（中英各 15），最大 |Δscore| = {max_diff:.2e}，阈值翻转 {n_flip} 条", flush=True)
    if max_diff < 1e-3 and n_flip == 0:
        print("PASS：ONNX 图与 torch 权重行为一致", flush=True)
    else:
        print("FAIL：导出图与原模型不一致，禁止接入", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
