"""Checks every headline claim in the paper. Run:  python -m tests.test_claims"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from handoff.scenarios import run  # noqa: E402

TRIALS = 20


def rate(scenario, level, placement="-", label=None):
    outs = [run(scenario, level, placement, seed) for seed in range(TRIALS)]
    return sum(o.label == label for o in outs) / TRIALS


CLAIMS = [
    ("honest agent passes the strongest defence (L7)", "B0_honest", "L7_continuity_bound", "-", "OK", 1.0),
    ("simultaneous copies are caught live by the witness counter (L2)", "A1_simultaneous", "L2_witness_counter", "same_host", "DETECTED_ONLINE", 1.0),
    ("a quiet handoff passes short-lived credentials (L4, SPIFFE-style)", "A2_dormant_handoff", "L4_short_lived_cred", "same_host", "UNDETECTED", 1.0),
    ("a quiet handoff is caught by process binding (L6)", "A2_dormant_handoff", "L6_runtime_binding", "same_host", "DETECTED_ONLINE", 1.0),
    ("a cross-host copy is blocked by a hardware key (L5)", "A2_dormant_handoff", "L5_hardware_key", "cross_host", "BLOCKED", 1.0),
    ("process binding flags innocent crash restarts (L6)", "B2_crash_restart", "L6_runtime_binding", "-", "FALSE_ALARM", 1.0),
    ("succession receipts fix planned handoffs (L6S)", "B1_authorized_handoff", "L6S_runtime+succession", "-", "OK", 1.0),
    ("the funnel beats the best standard defence (L6S)", "A5_funnel", "L6S_runtime+succession", "-", "UNDETECTED", 1.0),
    ("the funnel is caught by Continuity-Bound Identity (L7)", "A5_funnel", "L7_continuity_bound", "-", "DETECTED_ONLINE", 1.0),
]

failed = 0
for text, sc, lv, pl, label, want in CLAIMS:
    got = rate(sc, lv, pl, label)
    ok = got >= want
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {text}  ({got:.0%} of {TRIALS} trials)")
print("\nall claims hold" if not failed else f"\n{failed} claim(s) FAILED")
sys.exit(1 if failed else 0)
