"""Extract real agent action timing from the AI Village dataset (gated; accept terms on HF first).

    pip install datasets
    huggingface-cli login            # use the account that was granted access
    python -m experiments.calibrate_ai_village --inspect     # 1) look at the columns
    python -m experiments.calibrate_ai_village               # 2) write results/ai_village_gaps.json

Output: per-agent gaps (seconds) between consecutive computer-use turns, with long breaks
(overnight, session ends) removed. run_all.py uses these gaps instead of the assumed
lognormal "think time" when the file exists.
"""
import argparse
import collections
import json
import os
import statistics
from datetime import datetime

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
AGENT_FIELDS = ["agent_name", "agent", "agent_id", "model", "agent_slug"]
TIME_FIELDS = ["created_at", "timestamp", "time"]


def to_seconds(v):
    if isinstance(v, (int, float)):
        return v / 1000.0 if v > 1e11 else float(v)      # unix ms or s
    if isinstance(v, datetime):
        return v.timestamp()
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inspect", action="store_true", help="print columns and 3 rows, then stop")
    ap.add_argument("--max-gap", type=float, default=600.0, help="drop gaps longer than this (s): breaks, not work")
    ap.add_argument("--limit", type=int, default=0, help="only read this many rows (0 = all)")
    args = ap.parse_args()

    from datasets import load_dataset
    ds = load_dataset("aidigestorg/ai-village", "computer_use_turns", split="train", streaming=True)
    ds = ds.remove_columns([c for c in (ds.column_names or []) if "screenshot" in c or "image" in c]) \
        if ds.column_names else ds

    if args.inspect:
        for i, row in enumerate(ds):
            print({k: (str(v)[:80]) for k, v in row.items()})
            if i == 2:
                break
        return

    times = collections.defaultdict(list)
    agent_f = time_f = None
    for i, row in enumerate(ds):
        if agent_f is None:
            agent_f = next((f for f in AGENT_FIELDS if f in row), None)
            time_f = next((f for f in TIME_FIELDS if f in row), None)
            if not agent_f or not time_f:
                raise SystemExit(f"Could not find agent/time columns in {list(row)}; run --inspect and edit AGENT_FIELDS/TIME_FIELDS")
            print(f"using agent column '{agent_f}', time column '{time_f}'")
        times[str(row[agent_f])].append(to_seconds(row[time_f]))
        if args.limit and i + 1 >= args.limit:
            break

    gaps = {}
    for agent, ts in times.items():
        ts.sort()
        g = [b - a for a, b in zip(ts, ts[1:]) if 0 < b - a <= args.max_gap]
        if len(g) >= 50:
            gaps[agent] = g
    os.makedirs(OUT, exist_ok=True)
    json.dump(gaps, open(os.path.join(OUT, "ai_village_gaps.json"), "w"))
    for agent, g in sorted(gaps.items(), key=lambda kv: -len(kv[1])):
        print(f"{agent:30s} n={len(g):7d} median={statistics.median(g):6.1f}s mean={statistics.mean(g):6.1f}s")
    print(f"wrote {len(gaps)} agents -> results/ai_village_gaps.json")


if __name__ == "__main__":
    main()
