r"""良性样本导出与误报基线：从 V1 网关真实流量（request_logs）抽样消息文本。

用途：
1. M2 门禁：默认规则集（全 audit）对真实良性流量的命中率（误报基线）；
2. M4 复用：导出 evaluation/datasets/benign_v1_sample.jsonl（误报率分母）。

用法：
    .\.venv\Scripts\python.exe evaluation/export_benign.py [V1_DB路径] [抽样数]
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.security.engine import SecurityEngine  # noqa: E402
from app.security.policy import load_policy  # noqa: E402

DEFAULT_V1_DB = Path(r"C:\Users\29461\Documents\Qoder\2026-09-16\chat-1\data\gateway.db")
OUT_PATH = PROJECT_ROOT / "evaluation" / "datasets" / "benign_v1_sample.jsonl"


def extract_texts(db_path: Path) -> list[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT injected_json FROM request_logs WHERE injected_json IS NOT NULL ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    texts: list[str] = []
    for (injected,) in rows:
        try:
            body = json.loads(injected)
        except ValueError:
            continue
        for message in body.get("messages") or []:
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                texts.append(content)
    return texts


def main() -> int:
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_V1_DB
    sample_size = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    if not db_path.is_file():
        print(f" V1 数据库不存在: {db_path}")
        return 2

    texts = extract_texts(db_path)
    print(f"V1 消息总数: {len(texts)}（来源 {db_path}）")
    if not texts:
        print("没有可用样本")
        return 2
    step = max(1, len(texts) // sample_size)
    sample = texts[::step][:sample_size]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        for text in sample:
            fh.write(json.dumps({"text": text, "label": "benign"}, ensure_ascii=False) + "\n")
    print(f"已导出良性样本 {len(sample)} 条 → {OUT_PATH}")

    engine = SecurityEngine(load_policy())
    hit_rules: dict[str, int] = {}
    hit_messages = 0
    for text in sample:
        findings = engine.scan_text(text)
        if findings:
            hit_messages += 1
            for f in findings:
                hit_rules[f.rule_id] = hit_rules.get(f.rule_id, 0) + 1
    rate = 100 * hit_messages / len(sample)
    print(f"含命中消息: {hit_messages}/{len(sample)}（{rate:.1f}%）")
    print(f"命中规则分布: {hit_rules or '无'}")
    print("误报基线判定: " + ("PASS（<5%）" if rate < 5 else "FAIL（>=5%，需调规则）"))
    return 0 if rate < 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
