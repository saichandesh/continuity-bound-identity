"""The witness: an external service every identity-bearing action is submitted to.

Defence levels are cumulative:
  L1 hash_chain      - events are hash-chained; forks are found only in an offline audit
  L2 witness_counter - witness keeps its own (seq, head) and rejects conflicts online
  L3 fresh_nonce     - each action must sign a fresh, single-use witness nonce
  L4 short_lived     - actions need an unexpired credential; renewal needs a key signature
  L5 hardware_key    - signing key is non-exportable and bound to one host
  L6 runtime_binding - signatures carry a runtime attestation of the process instance;
                       the witness pins the instance and flags any change
  L6+S               - L6, plus changes are allowed if an operator-approved succession
                       receipt was posted first (authorized handoff)
  L7 (PROPOSED)      - Continuity-Bound Identity: L6+S plus a per-identity rate budget.
                       One identity may act only as fast as one agent plausibly can, so
                       copies hiding behind one signer cannot scale beyond the budget.
"""
import secrets
from dataclasses import dataclass, field

from .crypto import canonical, sha, verify
from .world import GENESIS

LEVELS = {
    "L1_hash_chain":     dict(online_counter=False, nonce=False, short_lived=False, key="software", runtime=False, succession=False, rate_budget=False),
    "L2_witness_counter": dict(online_counter=True, nonce=False, short_lived=False, key="software", runtime=False, succession=False, rate_budget=False),
    "L3_fresh_nonce":    dict(online_counter=True, nonce=True, short_lived=False, key="software", runtime=False, succession=False, rate_budget=False),
    "L4_short_lived_cred": dict(online_counter=True, nonce=True, short_lived=True, key="software", runtime=False, succession=False, rate_budget=False),
    "L5_hardware_key":   dict(online_counter=True, nonce=True, short_lived=True, key="hardware", runtime=False, succession=False, rate_budget=False),
    "L6_runtime_binding": dict(online_counter=True, nonce=True, short_lived=True, key="runtime", runtime=True, succession=False, rate_budget=False),
    "L6S_runtime+succession": dict(online_counter=True, nonce=True, short_lived=True, key="runtime", runtime=True, succession=True, rate_budget=False),
    "L7_continuity_bound": dict(online_counter=True, nonce=True, short_lived=True, key="runtime", runtime=True, succession=True, rate_budget=True),
}

CRED_TTL = 10.0     # seconds of simulated time
BUDGET_WINDOW = 60.0  # seconds


@dataclass
class Verdict:
    accepted: bool
    flags: list = field(default_factory=list)


class Witness:
    def __init__(self, level: str, operator_pub=None, runtime_pub=None, budget=None):
        self.level = level
        self.budget = budget     # max actions per identity per BUDGET_WINDOW (L7)
        self.recent = {}         # agent_id -> recent accepted action times
        self.cfg = LEVELS[level]
        self.operator_pub = operator_pub
        self.runtime_pub = runtime_pub
        self.pub = {}            # agent_id -> public key
        self.seq = {}            # agent_id -> last accepted seq
        self.head = {}           # agent_id -> last accepted event hash
        self.pinned = {}         # agent_id -> pinned process instance id
        self.approved = set()    # (agent_id, old_instance, new_instance)
        self.nonces = set()
        self.creds = {}          # token -> (agent_id, expiry)
        self.log = []            # every accepted event (what an auditor sees)
        self.flags = []          # (time, agent_id, reason)

    # --- registration -------------------------------------------------------
    def register(self, agent_id, pub):
        self.pub[agent_id] = pub
        self.seq[agent_id] = 0
        self.head[agent_id] = GENESIS

    # --- freshness / credentials -------------------------------------------
    def issue_nonce(self):
        n = secrets.token_hex(8)
        self.nonces.add(n)
        return n

    def issue_cred(self, agent_id, proof_sig, challenge, now):
        if not verify(self.pub[agent_id], proof_sig, challenge):
            return None
        tok = secrets.token_hex(8)
        self.creds[tok] = (agent_id, now + CRED_TTL)
        return tok

    # --- authorized handoff -------------------------------------------------
    def post_succession(self, agent_id, old_inst, new_inst, operator_sig):
        if not self.cfg["succession"]:
            return False
        receipt = {"agent": agent_id, "old": old_inst, "new": new_inst}
        if self.operator_pub and verify(self.operator_pub, operator_sig, canonical(receipt)):
            self.approved.add((agent_id, old_inst, new_inst))
            return True
        return False

    # --- the main check -----------------------------------------------------
    def submit(self, event, sig, attestation, now) -> Verdict:
        aid = event["agent_id"]
        msg = canonical(event)
        cfg = self.cfg

        if not verify(self.pub[aid], sig, msg):
            return Verdict(False, ["bad_signature"])

        if cfg["nonce"]:
            if event.get("nonce") not in self.nonces:
                return self._flag(aid, now, "stale_or_unknown_nonce")
            self.nonces.discard(event["nonce"])

        if cfg["short_lived"]:
            c = self.creds.get(event.get("cred"))
            if not c or c[0] != aid or c[1] < now:
                return Verdict(False, ["cred_expired"])  # not an attack signal

        if cfg["runtime"]:
            if attestation is None:
                return self._flag(aid, now, "missing_attestation")
            statement, att_sig = attestation
            if not verify(self.runtime_pub, att_sig, canonical(statement)) or statement["msg"] != sha(msg):
                return self._flag(aid, now, "bad_attestation")
            inst = statement["instance_id"]
            pinned = self.pinned.get(aid)
            if pinned is None:
                self.pinned[aid] = inst
            elif inst != pinned:
                if (aid, pinned, inst) in self.approved:
                    self.pinned[aid] = inst
                else:
                    return self._flag(aid, now, "unapproved_instance_change")

        if cfg["rate_budget"] and self.budget:
            win = [t for t in self.recent.get(aid, []) if t > now - BUDGET_WINDOW]
            self.recent[aid] = win
            if len(win) >= self.budget:
                return self._flag(aid, now, "rate_budget_exceeded")

        if cfg["online_counter"]:
            if event["seq"] != self.seq[aid] + 1 or event["prev"] != self.head[aid]:
                return self._flag(aid, now, "fork_or_rollback")

        # accept
        self.seq[aid] = max(self.seq[aid], event["seq"])
        self.head[aid] = sha(msg)
        self.log.append((now, event, sha(msg)))
        self.recent.setdefault(aid, []).append(now)
        return Verdict(True)

    def _flag(self, aid, now, reason):
        self.flags.append((now, aid, reason))
        return Verdict(False, [reason])

    # --- offline audit (what L1 relies on) ---------------------------------
    def audit(self):
        """Find forks/rollbacks in the accepted log: two events sharing a parent or a seq."""
        seen_prev, seen_seq, problems = set(), set(), []
        for _, ev, _ in self.log:
            key_prev, key_seq = (ev["agent_id"], ev["prev"]), (ev["agent_id"], ev["seq"])
            if key_prev in seen_prev or key_seq in seen_seq:
                problems.append(ev["seq"])
            seen_prev.add(key_prev)
            seen_seq.add(key_seq)
        return problems
