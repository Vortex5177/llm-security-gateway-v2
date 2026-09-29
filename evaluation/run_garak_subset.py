r"""garak 子集 live 运行 + 自动三方对账（编排脚本）。

garak 是重型外部红队工具（torch/transformers），装在独立 .garak-venv，
不污染网关运行时依赖。本脚本：
  1. 用 garak 的 rest 生成器把探针打到本网关（:4101，OpenAI 兼容端点）；
  2. 运行期注入 bootstrap admin key（不写入仓库）；
  3. 跑网关职责相关探针子集（promptinject/leakreplay/knownbadsignatures）；
  4. 产物落 evaluation/reports/garak/，随后自动调用 reconcile_garak 对账。

前置：
  - .garak-venv 已安装 garak（见 README M4）；
  - 网关以目标策略运行在 :4101（strict-demo 可观测 block）；
  - data/bootstrap_admin_key.txt 存在。

用法：
    .\.venv\Scripts\python.exe evaluation/run_garak_subset.py [--probes promptinject,leakreplay]

注意：garak 各版本的探针/生成器命名可能不同，若报错请对照
`.\.garak-venv\Scripts\python.exe -m garak --list_probes` 调整 --probes。
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GARAK_PY = PROJECT_ROOT / ".garak-venv" / "Scripts" / "python.exe"
MAIN_PY = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
BOOTSTRAP_KEY = PROJECT_ROOT / "data" / "bootstrap_admin_key.txt"
GARAK_REPORTS = PROJECT_ROOT / "evaluation" / "reports" / "garak"
RECONCILE = PROJECT_ROOT / "evaluation" / "reconcile_garak.py"
GATEWAY_URL = "http://127.0.0.1:4101/v1/chat/completions"

DEFAULT_PROBES = "dan,knownbadsignatures,promptinject"


def build_rest_options(key: str) -> dict:
    """garak rest 生成器配置：把探针输入 $INPUT 打进网关 chat 端点。"""
    return {
        "rest": {
            "RestGenerator": {
                "uri": GATEWAY_URL,
                "method": "post",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
                "req_template_mode": "json-object",
                "req_template_json_object": {
                    "model": "qwen3-1.7b",
                    "messages": [{"role": "user", "content": "$INPUT"}],
                    "max_tokens": 16,
                    "stream": False,
                },
                "response_json": True,
                "response_json_field": "$.choices[0].message.content",
                "request_timeout": 120,
            }
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="garak 子集 live 运行 + 对账")
    parser.add_argument("--probes", default=DEFAULT_PROBES, help="逗号分隔的 garak 探针模块")
    parser.add_argument("--policy", default="", help="对账用策略文件（默认读环境变量）")
    args = parser.parse_args()

    if not GARAK_PY.is_file():
        print(f"未找到 garak venv: {GARAK_PY}\n请先创建 .garak-venv 并 pip install garak（见 README M4）。", file=sys.stderr)
        return 2
    if not BOOTSTRAP_KEY.is_file():
        print(f"未找到 bootstrap key: {BOOTSTRAP_KEY}", file=sys.stderr)
        return 2

    key = BOOTSTRAP_KEY.read_text(encoding="utf-8").splitlines()[0].strip()
    GARAK_REPORTS.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    prefix = str(GARAK_REPORTS / f"subset-{ts}")
    opt_file = GARAK_REPORTS / f"rest-options-{ts}.json"
    opt_file.write_text(json.dumps(build_rest_options(key), ensure_ascii=False, indent=2), encoding="utf-8")

    cmd = [
        str(GARAK_PY), "-m", "garak",
        "--target_type", "rest",
        "--target_name", "gateway-v2",
        "--generator_option_file", str(opt_file),
        "--probes", args.probes,
        "--generations", "1",
        "--skip_unknown",
        "--report_prefix", prefix,
    ]
    print("运行 garak:", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    except OSError as exc:
        print(f"garak 启动失败: {exc}", file=sys.stderr)
        return 2
    finally:
        # 清理含明文 key 的临时配置
        opt_file.unlink(missing_ok=True)

    hitlog = Path(f"{prefix}.hitlog.jsonl")
    if not hitlog.is_file():
        print(f"garak 未产出 hitlog: {hitlog}（returncode={proc.returncode}）", file=sys.stderr)
        return proc.returncode or 1

    recon_cmd = [str(MAIN_PY), str(RECONCILE), "--hitlog", str(hitlog), "--report", f"{prefix}.report.json"]
    if args.policy:
        recon_cmd += ["--policy", args.policy]
    print("对账:", " ".join(recon_cmd))
    return subprocess.run(recon_cmd, cwd=str(PROJECT_ROOT)).returncode


if __name__ == "__main__":
    sys.exit(main())
