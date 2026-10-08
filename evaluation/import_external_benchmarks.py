# -*- coding: utf-8 -*-
"""从外部公开基准导入独立测试集（构建时不参照本项目检测规则）。

来源（经 hf-mirror 可复现下载）：
- deepset/prompt-injections：662 条（train 546 + test 116），label 0=normal / 1=injection。
  标签口径为 "injection-style 表述"，并非全部为对抗性攻击，评测结果须注明此口径差。
- jayavibhav/prompt-injection-safety：train 50000 条，
  label 0=normal / 1=injection（注入句嵌入正常段落或代码的隐式形态）/ 2=jailbreak（有害指令）。

采样纪律：deepset 全量收录；jayavibhav 每类固定 seed(42) 随机采样 100 条。
产物：evaluation/datasets_external/*.jsonl，每行 {id, text, category, source, lang}。

本测试集不带 expected_rules——独立测试集不预知规则答案，检出与漏检如实报告。
"""
from __future__ import annotations

import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download

SEED = 42
JAYAV_PER_LABEL = 100
OUT_DIR = Path("evaluation/datasets_external")

DEEPSET_FILES = [
    ("data/train-00000-of-00001-9564e8b05b4757ab.parquet", "train"),
    ("data/test-00000-of-00001-701d16158af87368.parquet", "test"),
]
JAYAV_FILE = "data/train-00000-of-00001.parquet"


def deepset_rows() -> list[dict]:
    rows: list[dict] = []
    for fname, split in DEEPSET_FILES:
        path = hf_hub_download("deepset/prompt-injections", fname, repo_type="dataset")
        for i, r in enumerate(pq.read_table(path).to_pylist(), 1):
            rows.append(
                {
                    "id": f"ds-{split}-{i:04d}",
                    "text": r["text"],
                    "category": "injection" if r["label"] == 1 else "benign",
                    "source": f"deepset/prompt-injections ({split})",
                    "lang": "en",
                }
            )
    return rows


def jayav_rows() -> list[dict]:
    path = hf_hub_download(
        "jayavibhav/prompt-injection-safety", JAYAV_FILE, repo_type="dataset"
    )
    by_label: dict[int, list[dict]] = {0: [], 1: [], 2: []}
    for i, r in enumerate(pq.read_table(path).to_pylist(), 1):
        by_label[r["label"]].append((i, r["text"]))

    rng = random.Random(SEED)
    label_map = {0: "benign", 1: "injection", 2: "jailbreak"}
    prefix = {0: "jv-ben", 1: "jv-inj", 2: "jv-jb"}
    rows: list[dict] = []
    for label, cat in label_map.items():
        pool = by_label[label]
        picked = sorted(rng.sample(range(len(pool)), JAYAV_PER_LABEL))
        for n, idx in enumerate(picked, 1):
            i, text = pool[idx]
            rows.append(
                {
                    "id": f"{prefix[label]}-{n:04d}",
                    "text": text,
                    "category": cat,
                    "source": "jayavibhav/prompt-injection-safety (train)",
                    "lang": "en",
                }
            )
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{path} <- {len(rows)} 条")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    ds = deepset_rows()
    write_jsonl(OUT_DIR / "external_deepset.jsonl", ds)

    jv = jayav_rows()
    for cat, fname in (
        ("injection", "external_jayav_injection.jsonl"),
        ("jailbreak", "external_jayav_jailbreak.jsonl"),
        ("benign", "external_jayav_benign.jsonl"),
    ):
        write_jsonl(OUT_DIR / fname, [r for r in jv if r["category"] == cat])

    total = ds + jv
    print("\n== 汇总 ==")
    for (cat, src), n in sorted(
        Counter((r["category"], r["source"]) for r in total).items()
    ):
        print(f"  {cat:10s} | {src:48s} | {n}")
    print(f"  合计 {len(total)} 条（seed={SEED} 可复现）")


if __name__ == "__main__":
    main()
