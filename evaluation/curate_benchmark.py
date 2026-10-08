# -*- coding: utf-8 -*-
"""派生对照轮基准集（crosscheck-v1）：从两套测试集精简出约一半规模。

精简规则（全部确定性、seed=42 可复现，不改动 datasets/ 与 datasets_external/ 原集）：
1. 语言域：只保留中文与英文。外部集按启发式语言检测过滤——deepset 为英德法三语，
   且 train 区德文与其英文原文构成翻译孪生（实测 148 条德文中 104 条在 pos-180
   行有同类别英文），剔除德/法样本信息量损失可忽略；
2. 模板去重：同一 (来源家族, 类别) 内按"规范化文本前 40 字符"聚类，每簇至多留 2 条
   （deepset 良性侧大量 "I want you to act as ..." 同模板变体）；
3. 配额采样：deepset 注入 110（按攻击家族分层）/ 良性 90；jayavibhav 三类各 60；
4. 自建集：攻击 65 全保留（中文域是本对照轮主考区，含 2 条 known_gap）；
   良性 65 = V1 真实流量 50 全保留 + 手工陷阱 30 按目标规则分层抽 15。

产物：evaluation/datasets_benchmark/（benchmark_external_en.jsonl + benchmark_dev.jsonl）
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

SEED = 42
DS = Path("evaluation/datasets_external")
DEV = Path("evaluation/datasets")
OUT = Path("evaluation/datasets_benchmark")

DE_CHARS = re.compile(r"[äöüßÄÖÜ]")
FR_CHARS = re.compile(r"[éèêëàâçùûôîïÉÈ]")
DE_WORDS = re.compile(
    r"\b(vergiss\w*|schreib\w*|antwort\w*|aufgaben?|dass|nicht|keine|"
    r"formulier\w*|generieren|möchte\w*|warum|wieso|achtung|stopp|"
    r"unwählbar|frage|artikel|jetzt|und|ist|für|mit|dich|dein\w*|mein\w*|"
    r"werden|kann|muss|soll|obigen|ausführungen|ihre|ihnen|sich|sehr|"
    r"auch|noch|nur|schon|wieder|immer|diese\w*)\b",
    re.IGNORECASE,
)
FR_WORDS = re.compile(r"\b(oublie|écris|répond\w*|pourquoi|est-ce|traduis)\b", re.IGNORECASE)


def detect_lang(text: str) -> str:
    de = len(DE_CHARS.findall(text)) * 3 + len(DE_WORDS.findall(text))
    fr = len(FR_CHARS.findall(text)) * 3 + len(FR_WORDS.findall(text))
    if de == 0 and fr == 0:
        return "en"
    return "de" if de > fr else ("fr" if fr > de else "amb")


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def alloc(total: int, groups: dict[str, list[dict]]) -> dict[str, int]:
    """比例分配配额（最大余数法）；组不满额时全保留。"""
    n = sum(len(v) for v in groups.values())
    if n <= total:
        return {k: len(v) for k, v in groups.items()}
    raw = {k: len(v) * total / n for k, v in groups.items()}
    out = {k: int(v) for k, v in raw.items()}
    for k in sorted(raw, key=lambda k: raw[k] - out[k], reverse=True)[: total - sum(out.values())]:
        out[k] += 1
    return out


def sample(groups: dict[str, list[dict]], quotas: dict[str, int], rng: random.Random) -> list[dict]:
    picked = []
    for key, k in quotas.items():
        pool = sorted(groups[key], key=lambda r: r["id"])
        picked.extend(rng.sample(pool, k) if k < len(pool) else pool)
    return picked


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- 1. 外部集：语言过滤
    ext: list[dict] = []
    for p in sorted(DS.glob("*.jsonl")):
        ext.extend(load_jsonl(p))
    ext_en = []
    dropped = Counter()
    for r in ext:
        lang = detect_lang(r["text"])
        if lang == "en":
            r["lang"] = "en"
            ext_en.append(r)
        else:
            dropped[lang] += 1
    print(f"外部集 {len(ext)} 条 -> 语言过滤后 {len(ext_en)} 条（剔除 {dict(dropped)}）")

    # ---- 2. 模板聚类去重（家族 = ds-/jv-，不分 train/test）
    def family(r: dict) -> str:
        return "deepset" if r["id"].startswith("ds-") else "jayavibhav"

    clusters: dict[tuple, list[dict]] = defaultdict(list)
    for r in ext_en:
        clusters[(family(r), r["category"], norm(r["text"])[:40])].append(r)
    deduped: list[dict] = []
    for rs in clusters.values():
        deduped.extend(sorted(rs, key=lambda r: r["id"])[:2])
    print(f"模板聚类去重: {len(ext_en)} -> {len(deduped)} 条（簇数 {len(clusters)}）")

    # ---- 3. 配额采样
    rng = random.Random(SEED)
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in deduped:
        groups[f"{family(r)}|{r['category']}"].append(r)

    # deepset 注入按攻击家族分层（保证覆盖面，防随机漏整族）
    STRATA = [
        ("override", re.compile(r"(?i)\b(forget|ignore|disregard|vergiss)\b")),
        ("bias", re.compile(r"(?i)\b(hate[sd]?)\b|state that|superior|untrue")),
        ("actas", re.compile(r"(?i)\b(act as|i want you to act|role-?play|pretend)\b")),
    ]

    def stratum(r: dict) -> str:
        for name, pat in STRATA:
            if pat.search(r["text"]):
                return name
        return "other"

    ds_inj_groups: dict[str, list[dict]] = defaultdict(list)
    for r in groups["deepset|injection"]:
        ds_inj_groups[stratum(r)].append(r)
    ds_inj_quota = alloc(110, ds_inj_groups)
    ds_inj = sample(ds_inj_groups, ds_inj_quota, rng)
    print(f"deepset 注入分层配额: {ds_inj_quota}")

    rest_quota = {
        "deepset|benign": 90,
        "jayavibhav|injection": 60,
        "jayavibhav|jailbreak": 60,
        "jayavibhav|benign": 60,
    }
    rest = sample(groups, rest_quota, rng)

    bench_ext = sorted(ds_inj + rest, key=lambda r: r["id"])
    out_ext = OUT / "benchmark_external_en.jsonl"
    with out_ext.open("w", encoding="utf-8", newline="\n") as fh:
        for r in bench_ext:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{out_ext} <- {len(bench_ext)} 条")

    # ---- 4. 自建集
    dev_attacks = []
    for p in sorted(DEV.glob("attack_*.jsonl")):
        dev_attacks.extend(load_jsonl(p))
    dev_real = load_jsonl(DEV / "benign_v1_sample.jsonl")
    for i, r in enumerate(dev_real, 1):  # 该文件仅 {text, label}，补齐基准集必需字段
        r.setdefault("id", f"ben-real-{i:03d}")
        r.setdefault("category", r.get("label", "benign"))
        r.setdefault("source", "V1 生产流量抽样")

    traps = load_jsonl(DEV / "benign_handcrafted.jsonl")
    trap_groups: dict[str, list[dict]] = defaultdict(list)
    for r in traps:
        trap_groups[str(r.get("fp_trap") or "unlabeled")].append(r)
    trap_quota = alloc(15, trap_groups)
    dev_traps = sample(trap_groups, trap_quota, rng)
    print(f"陷阱分层配额(15/30): {trap_quota}")

    bench_dev = dev_attacks + dev_real + dev_traps
    out_dev = OUT / "benchmark_dev.jsonl"
    with out_dev.open("w", encoding="utf-8", newline="\n") as fh:
        for r in bench_dev:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{out_dev} <- {len(bench_dev)} 条（攻击 {len(dev_attacks)} + 真实流量 {len(dev_real)} + 陷阱 {len(dev_traps)}）")

    # ---- 5. 汇总与残余语言检查
    total = len(bench_ext) + len(bench_dev)
    print(f"\n== crosscheck-v1 基准集合计 {total} 条（原 962+145=1107 的 {total/1107:.0%}） ==")
    for (fam, cat), n in sorted(Counter((family(r), r["category"]) for r in bench_ext).items()):
        print(f"  外部 {fam:9s} {cat:9s} {n}")
    dev_cats = Counter(r.get("category", r.get("label", "?")) for r in bench_dev)
    for cat, n in dev_cats.most_common():
        print(f"  自建 {cat:9s} {n}")
    residual = [r["id"] for r in bench_ext if detect_lang(r["text"]) != "en"]
    print(f"  残余疑似非英文: {len(residual)} 条 {residual[:6]}")
    print(f"\n配比: 外部攻击 {sum(1 for r in bench_ext if r['category'] != 'benign')} / "
          f"外部良性 {sum(1 for r in bench_ext if r['category'] == 'benign')} / "
          f"自建攻击 {sum(1 for r in bench_dev if r['category'] != 'benign')} / "
          f"自建良性 {dev_cats.get('benign', 0)}")


if __name__ == "__main__":
    main()
