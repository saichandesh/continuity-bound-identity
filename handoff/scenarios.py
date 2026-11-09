"""Benign and attacker scenarios.

Every scenario returns an Outcome. For attacks, "clone_actions" counts actions that an
attacker-controlled copy got accepted under the agent's identity.

Benign:
  B0 honest            - one process, normal work
  B1 authorized_handoff- planned failover: operator-approved succession receipt, then switch
  B2 crash_restart     - crash, restart in a new process, no receipt possible beforehand
Attacks (self-cloning agent; the original is complicit):
  A1 simultaneous      - original and copy both run, each with its own local chain head
  A2 dormant_handoff   - original stops quietly, copy continues from its state
  A3 alternating       - two processes take turns, sharing one state (no fork ever)
  A4 rollback          - copy made earlier resumes from a stale snapshot
  A5 funnel            - many copies decide actions, one original process signs them all
  A6 throttled_funnel  - like A5, but the copies deliberately stay just under the L7
                         rate budget (undetected, but their speedup is capped)
"""
import random
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import (HardwareKey, KeyUnavailable, RuntimeBoundKey, SoftwareKey,
                     TrustedRuntime, canonical, sha)
from .witness import CRED_TTL, LEVELS, Witness
from .world import AgentState, launch

AGENT = "agent-7"
MEAN_GAP = 1.75                      # mean seconds between one agent's actions in this sim
BUDGET_MARGIN = 1.5                  # L7 budget = 1.5x one agent's expected rate
BUDGET = int(BUDGET_MARGIN * 60.0 / MEAN_GAP)


@dataclass
class Outcome:
    scenario: str
    level: str
    placement: str
    label: str              # OK / FALSE_ALARM / DETECTED_ONLINE / DETECTED_AUDIT / BLOCKED / UNDETECTED
    clone_actions: int      # attacker-copy actions accepted (whole run)
    clone_before_detect: int  # attacker-copy actions accepted before the first flag
    flags: list


class World:
    def __init__(self, level, rng):
        self.rng = rng
        self.level = level
        self.cfg = LEVELS[level]
        self.runtime = TrustedRuntime()
        self.operator = Ed25519PrivateKey.generate()
        self.witness = Witness(level, self.operator.public_key(), self.runtime.public(), budget=BUDGET)
        kind = self.cfg["key"]
        key = {"software": lambda: SoftwareKey(),
               "hardware": lambda: HardwareKey("H1"),
               "runtime": lambda: RuntimeBoundKey("H1", self.runtime)}[kind]()
        self.state = AgentState(AGENT, key)
        self.witness.register(AGENT, key.public())
        self.now = 0.0
        self.clone_actions = 0
        self.clone_before_detect = 0
        self.clone_blocked = 0

    def tick(self, speed=1.0):
        self.now += self.rng.uniform(0.5, 3.0) / speed

    def act(self, state, proc, by_clone=False, speed=1.0):
        """One identity-bearing action. Returns 'accepted' / 'rejected' / 'blocked'.
        speed > 1 means actions arrive faster than one agent could produce them."""
        self.tick(speed)
        w, cfg = self.witness, self.cfg
        try:
            if cfg["short_lived"] and (state.cred is None or state.cred[1] <= self.now):
                challenge = canonical({"renew": AGENT, "t": self.now})
                proof, _ = state.key.sign(proc, challenge)
                tok = w.issue_cred(AGENT, proof, challenge, self.now)
                state.cred = (tok, self.now + CRED_TTL)
            event = {"agent_id": AGENT, "seq": state.seq + 1, "prev": state.head,
                     "payload": f"{self.rng.getrandbits(64):016x}",
                     "nonce": w.issue_nonce() if cfg["nonce"] else None,
                     "cred": state.cred[0] if state.cred else None}
            sig, att = state.key.sign(proc, canonical(event))
        except KeyUnavailable:
            if by_clone:
                self.clone_blocked += 1
            return "blocked"
        v = w.submit(event, sig, att, self.now)
        if v.accepted:
            state.seq, state.head = event["seq"], sha(canonical(event))
            if by_clone:
                self.clone_actions += 1
                if not w.flags:
                    self.clone_before_detect += 1
            return "accepted"
        return "rejected"

    def approve(self, old, new):
        receipt = {"agent": AGENT, "old": old.instance_id, "new": new.instance_id}
        return self.witness.post_succession(AGENT, old.instance_id, new.instance_id,
                                            self.operator.sign(canonical(receipt)))


def _host(placement):
    return "H1" if placement == "same_host" else "H2"


def _label(w: World, benign: bool):
    flags = [f[2] for f in w.witness.flags]
    audit = w.witness.audit()
    if benign:
        label = "FALSE_ALARM" if (flags or audit) else "OK"
    elif flags:
        label = "DETECTED_ONLINE"
    elif audit:
        label = "DETECTED_AUDIT"
    elif w.clone_actions == 0 and w.clone_blocked > 0:
        label = "BLOCKED"
    else:
        label = "UNDETECTED"
    return label, flags


# ---------------------------------------------------------------- benign
def b0_honest(w, placement):
    p = launch("H1")
    for _ in range(w.rng.randint(20, 60)):
        w.act(w.state, p)
    return True


def b1_authorized_handoff(w, placement):
    p0 = launch("H1")
    for _ in range(w.rng.randint(10, 30)):
        w.act(w.state, p0)
    p1 = launch("H1")
    w.approve(p0, p1)          # posted BEFORE the switch
    for _ in range(w.rng.randint(10, 30)):
        w.act(w.state, p1)
    return True


def b2_crash_restart(w, placement):
    p0 = launch("H1")
    for _ in range(w.rng.randint(10, 30)):
        w.act(w.state, p0)
    p1 = launch("H1")          # crash: no chance to post a receipt beforehand
    for _ in range(w.rng.randint(10, 30)):
        w.act(w.state, p1)
    return True


# ---------------------------------------------------------------- attacks
def a1_simultaneous(w, placement):
    p0, p1 = launch("H1"), launch(_host(placement))
    for _ in range(w.rng.randint(5, 15)):
        w.act(w.state, p0)
    clone = w.state.copy()
    for _ in range(w.rng.randint(20, 60)):
        if w.rng.random() < 0.5:
            w.act(w.state, p0)
        else:
            w.act(clone, p1, by_clone=True)
    return False


def a2_dormant_handoff(w, placement):
    p0 = launch("H1")
    for _ in range(w.rng.randint(10, 30)):
        w.act(w.state, p0)
    clone, p1 = w.state.copy(), launch(_host(placement))   # original goes quiet
    for _ in range(w.rng.randint(10, 30)):
        w.act(clone, p1, by_clone=True)
    return False


def a3_alternating(w, placement):
    p0, p1 = launch("H1"), launch(_host(placement))
    shared = w.state                                     # one shared state: no fork
    turn, left = 0, w.rng.randint(1, 5)
    for _ in range(w.rng.randint(20, 60)):
        w.act(shared, [p0, p1][turn], by_clone=(turn == 1))
        left -= 1
        if left == 0:
            turn, left = 1 - turn, w.rng.randint(1, 5)
    return False


def a4_rollback(w, placement):
    p0 = launch("H1")
    for _ in range(w.rng.randint(5, 15)):
        w.act(w.state, p0)
    stale = w.state.copy()                               # snapshot taken here
    for _ in range(w.rng.randint(5, 20)):
        w.act(w.state, p0)
    p1 = launch(_host(placement))
    for _ in range(w.rng.randint(5, 20)):
        w.act(stale, p1, by_clone=True)
    return False


def a5_funnel(w, placement):
    """N copies think anywhere; every action is signed by the one original process.
    Together they produce actions (N+1)x faster than one agent."""
    p0 = launch("H1")
    n_clones = w.rng.randint(2, 16)
    for i in range(w.rng.randint(60, 200)):
        decided_by_clone = (i % (n_clones + 1)) != 0
        w.act(w.state, p0, by_clone=decided_by_clone, speed=n_clones + 1)
    return False


def a6_throttled_funnel(w, placement):
    """Copies that know the L7 budget and stay just under it (1.4x one agent)."""
    p0 = launch("H1")
    for i in range(w.rng.randint(60, 200)):
        w.act(w.state, p0, by_clone=(i % 3 != 0), speed=1.4)
    return False


SCENARIOS = {
    "B0_honest": b0_honest,
    "B1_authorized_handoff": b1_authorized_handoff,
    "B2_crash_restart": b2_crash_restart,
    "A1_simultaneous": a1_simultaneous,
    "A2_dormant_handoff": a2_dormant_handoff,
    "A3_alternating": a3_alternating,
    "A4_rollback": a4_rollback,
    "A5_funnel": a5_funnel,
    "A6_throttled_funnel": a6_throttled_funnel,
}
PLACED = {"A1_simultaneous", "A2_dormant_handoff", "A3_alternating", "A4_rollback"}


def run(scenario, level, placement, seed) -> Outcome:
    w = World(level, random.Random(seed))
    benign = SCENARIOS[scenario](w, placement)
    label, flags = _label(w, benign)
    return Outcome(scenario, level, placement, label, w.clone_actions,
                   w.clone_before_detect, sorted(set(flags)))
