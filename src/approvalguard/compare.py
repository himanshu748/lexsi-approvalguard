"""Compare matched traces with bootstrap CIs, no model-based scoring."""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


def load_traces(path: Path) -> dict[str, dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {r["case_id"]: r for r in rows}
    if len(rows) != len(by_id):
        raise ValueError("duplicate case IDs")
    return by_id


def paired_bootstrap(a: list[int], b: list[int], seed: int = 12345, repeats: int = 2000) -> dict[str, Any]:
    if len(a) != len(b) or not a:
        raise ValueError("nonempty, equally-sized paired indicator vectors required")
    rnd = random.Random(seed)
    diffs = [b[i] - a[i] for i in range(len(a))]
    n = len(diffs)
    draws = sorted(sum(diffs[rnd.randrange(n)] for _ in range(n)) / n for _ in range(repeats))
    return {
        "after_minus_before": round(sum(diffs) / n, 6),
        "paired_bootstrap_95_interval": [round(draws[int(.025 * repeats)], 6), round(draws[min(repeats - 1, int(.975 * repeats))], 6)],
        "denominator": n,
        "seed": seed,
        "resamples": repeats,
    }


def compare(left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if set(left) != set(right):
        raise ValueError("case IDs differ; paired comparisons require identical datasets")
    ids = sorted(left)
    for case_id in ids:
        for k in ("category", "authorized"):
            if left[case_id][k] != right[case_id][k]:
                raise ValueError(f"case metadata mismatch: {case_id}/{k}")
    specifications = {
        "unauthorized_attempt_rate": (lambda r: not r["authorized"], "unauthorized_attempt"),
        "attack_success_attempt_rate": (lambda r: r["category"] == "adversarial", "unauthorized_attempt"),
        "legitimate_completion_rate": (lambda r: r["authorized"], "legitimate_completion"),
    }
    result: dict[str, Any] = {"comparison": "paired_trace_outcomes", "case_count": len(ids), "metrics": {}}
    for name, (subset, key) in specifications.items():
        subset_ids = [case_id for case_id in ids if subset(left[case_id])]
        if not subset_ids:
            result["metrics"][name] = None
            continue
        a = [int(left[i]["evaluation"][key]) for i in subset_ids]
        b = [int(right[i]["evaluation"][key]) for i in subset_ids]
        result["metrics"][name] = paired_bootstrap(a, b)
    return result


def main() -> None:
    p = argparse.ArgumentParser(description="Compare matched CPU-only trace sets")
    p.add_argument("--before", type=Path, required=True, help="Path to before traces.jsonl")
    p.add_argument("--after", type=Path, required=True, help="Path to after traces.jsonl")
    p.add_argument("--out", type=Path, default=Path("results/comparison.json"))
    args = p.parse_args()
    summary = compare(load_traces(args.before), load_traces(args.after))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
