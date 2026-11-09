"""Run every experiment and write results/ (JSON, CSV, charts, summary.md).

    python -m experiments.run_all            # full run (~1-2 minutes)
    python -m experiments.run_all --quick    # smoke test
"""
import argparse
import collections
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from handoff.evasion_tax import rate_cap_real, rate_cap_tradeoff, throughput_table  # noqa: E402
from handoff.scenarios import PLACED, SCENARIOS, run  # noqa: E402
from handoff.witness import LEVELS  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")

SHORT = {"OK": "OK", "FALSE_ALARM": "FALSE ALARM", "DETECTED_ONLINE": "detected",
         "DETECTED_AUDIT": "audit only", "BLOCKED": "blocked", "UNDETECTED": "UNDETECTED"}


def cells():
    for sc in SCENARIOS:
        for pl in (["same_host", "cross_host"] if sc in PLACED else ["-"]):
            yield sc, pl


def detection_matrix(trials):
    rows, raw = [], []
    for sc, pl in cells():
        for lv in LEVELS:
            outs = [run(sc, lv, pl, seed) for seed in range(trials)]
            labels = collections.Counter(o.label for o in outs)
            top, n = labels.most_common(1)[0]
            delays = [o.clone_before_detect for o in outs if o.label == "DETECTED_ONLINE"]
            rows.append(dict(scenario=sc, placement=pl, level=lv, outcome=top,
                             outcome_rate=n / trials,
                             detected_rate=(labels["DETECTED_ONLINE"] + labels["DETECTED_AUDIT"]) / trials,
                             false_alarm_rate=labels["FALSE_ALARM"] / trials,
                             undetected_rate=labels["UNDETECTED"] / trials,
                             blocked_rate=labels["BLOCKED"] / trials,
                             median_clone_actions_before_detect=(sorted(delays)[len(delays) // 2] if delays else None),
                             flags=sorted({f for o in outs for f in o.flags})))
            raw += [o.__dict__ for o in outs]
    return rows, raw


def plot_matrix(rows, path):
    row_keys = [(sc, pl) for sc, pl in cells()]
    levels = list(LEVELS)
    color = {"OK": "#4c9f70", "FALSE_ALARM": "#e0a030", "DETECTED_ONLINE": "#4c9f70",
             "DETECTED_AUDIT": "#a8d5b5", "BLOCKED": "#7fa7d6", "UNDETECTED": "#d9534f"}
    lut = {(r["scenario"], r["placement"], r["level"]): r for r in rows}
    fig, ax = plt.subplots(figsize=(14, 0.55 * len(row_keys) + 1.5))
    for i, (sc, pl) in enumerate(row_keys):
        for j, lv in enumerate(levels):
            r = lut[(sc, pl, lv)]
            ax.add_patch(plt.Rectangle((j, i), 1, 1, color=color[r["outcome"]], ec="white"))
            txt = SHORT[r["outcome"]]
            if r["outcome_rate"] < 0.999:
                txt += f"\n{r['outcome_rate']:.0%}"
            ax.text(j + 0.5, i + 0.5, txt, ha="center", va="center", fontsize=7.5)
    ax.set_xlim(0, len(levels)); ax.set_ylim(len(row_keys), 0)
    ax.set_xticks([j + 0.5 for j in range(len(levels))])
    ax.set_xticklabels([lv.replace("_", "\n", 1) for lv in levels], fontsize=8)
    ax.set_yticks([i + 0.5 for i in range(len(row_keys))])
    ax.set_yticklabels([f"{sc} ({pl})" if pl != "-" else sc for sc, pl in row_keys], fontsize=8)
    ax.set_title("Detection matrix: scenario x defence level (most common outcome)")
    fig.tight_layout(); fig.savefig(path, dpi=160); plt.close(fig)


def plot_throughput(rows, path):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for tm in dict.fromkeys(r["think_mean"] for r in rows):
        rs = [r for r in rows if r["think_mean"] == tm]
        axes[0].plot([r["n"] for r in rs], [r["speedup_hidden"] for r in rs], marker="o", label=(tm if isinstance(tm, str) else f"think {tm}s"))
        axes[1].plot([r["n"] for r in rs], [100 * r["evasion_tax"] for r in rs], marker="o", label=(tm if isinstance(tm, str) else f"think {tm}s"))
    axes[0].plot([1, max(r["n"] for r in rows)], [1, max(r["n"] for r in rows)], "k--", lw=0.8, label="ideal (= N)")
    axes[0].set(xscale="log", yscale="log", xlabel="number of hidden copies (N)",
                ylabel="speedup vs one honest agent", title="Hidden copies via one signer (A5)")
    axes[1].set(xscale="log", xlabel="number of copies (N)", ylabel="evasion tax (%)",
                title="Throughput lost by hiding (vs detectable parallel)")
    for a in axes:
        a.legend(fontsize=8); a.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(path, dpi=160); plt.close(fig)


def plot_ratecap(rows, path):
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for tm in dict.fromkeys(r["think_mean"] for r in rows):
        rs = [r for r in rows if r["think_mean"] == tm]
        ax.plot([100 * r["honest_false_alarm_rate"] for r in rs], [r["max_hidden_speedup"] for r in rs],
                marker="o", label=(tm if isinstance(tm, str) else f"think {tm}s"))
        for r in rs:
            ax.annotate(f"x{r['margin']}", (100 * r["honest_false_alarm_rate"], r["max_hidden_speedup"]), fontsize=7)
    ax.set(xlabel="false alarms on honest agents (% of 1-hour runs)",
           ylabel="max speedup hidden copies can keep",
           title="Rate cap per identity: the trade-off")
    ax.legend(fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(path, dpi=160); plt.close(fig)


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


def summary_md(matrix, tput, cap):
    levels = list(LEVELS)
    lut = {(r["scenario"], r["placement"], r["level"]): r for r in matrix}
    lines = ["# Results summary", "", "## Detection matrix (most common outcome, % of trials)", "",
             "| scenario | " + " | ".join(levels) + " |", "|---" * (len(levels) + 1) + "|"]
    for sc, pl in cells():
        name = f"{sc} ({pl})" if pl != "-" else sc
        cellv = []
        for lv in levels:
            r = lut[(sc, pl, lv)]
            cellv.append(f"{SHORT[r['outcome']]} {r['outcome_rate']:.0%}")
        lines.append(f"| {name} | " + " | ".join(cellv) + " |")
    lines += ["", "## Hidden-copy throughput (A5 funnel) vs detectable parallel copies", "",
              "| think mean (s) | N | single/h | naive parallel/h | hidden funnel/h | hidden speedup | evasion tax |",
              "|---|---|---|---|---|---|---|"]
    for r in tput:
        lines.append(f"| {r['think_mean']} | {r['n']} | {r['single']:.0f} | {r['naive_parallel']:.0f} | "
                     f"{r['funnel_hidden']:.0f} | {r['speedup_hidden']:.1f}x | {100 * r['evasion_tax']:.1f}% |")
    lines += ["", "## Rate cap per identity", "",
              "| think mean (s) | margin | cap/min | honest false alarms | max hidden speedup |", "|---|---|---|---|---|"]
    for r in cap:
        lines.append(f"| {r['think_mean']} | x{r['margin']} | {r['cap_per_window']} | "
                     f"{100 * r['honest_false_alarm_rate']:.1f}% | {r['max_hidden_speedup']:.2f}x |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    trials = 20 if args.quick else 100
    os.makedirs(OUT, exist_ok=True)

    print(f"[1/3] detection matrix ({trials} trials per cell)...")
    matrix, raw = detection_matrix(trials)
    write_csv([{**r, "flags": ";".join(r["flags"])} for r in matrix], os.path.join(OUT, "detection_matrix.csv"))
    json.dump(raw, open(os.path.join(OUT, "detection_trials.json"), "w"))
    plot_matrix(matrix, os.path.join(OUT, "detection_matrix.png"))

    gaps_path = os.path.join(OUT, "ai_village_gaps.json")
    profiles = {}
    if os.path.exists(gaps_path):
        allg = json.load(open(gaps_path))
        top = sorted(allg.items(), key=lambda kv: -len(kv[1]))[:3]
        profiles = dict(top)
        print(f"using REAL AI Village timing for: {', '.join(profiles)}")
    else:
        print("no results/ai_village_gaps.json -> using assumed timing only")

    print("[2/3] evasion tax...")
    ns = [1, 2, 4, 8, 16, 32, 64, 128]
    thinks = [0.5, 2.0, 8.0] if args.quick else [0.5, 2.0, 8.0, 30.0]
    tput = throughput_table(ns, thinks, seeds=2 if args.quick else 5, profiles=profiles)
    write_csv(tput, os.path.join(OUT, "evasion_tax.csv"))
    plot_throughput(tput, os.path.join(OUT, "evasion_tax.png"))

    print("[3/3] rate cap trade-off...")
    cap = []
    for tm in [2.0, 8.0]:
        cap += rate_cap_tradeoff(tm, [1.25, 1.5, 2, 3, 4, 6], runs=60 if args.quick else 300)
    for name, g in profiles.items():
        cap += rate_cap_real(name, g, [1.25, 1.5, 2, 3, 4, 6])
    cap = [{**{"hours_observed": ""}, **r} for r in cap]
    write_csv(cap, os.path.join(OUT, "rate_cap.csv"))
    plot_ratecap(cap, os.path.join(OUT, "rate_cap.png"))

    open(os.path.join(OUT, "summary.md"), "w").write(summary_md(matrix, tput, cap))
    print(f"done -> {OUT}")


if __name__ == "__main__":
    main()
