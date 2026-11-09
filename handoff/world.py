"""Processes and agent state."""
import itertools
import secrets
from dataclasses import dataclass

GENESIS = "0" * 64
_ids = itertools.count(1)


@dataclass(frozen=True)
class Process:
    host: str
    instance_id: str


def launch(host: str) -> Process:
    """A trusted runtime assigns a fresh instance id at every process launch."""
    return Process(host=host, instance_id=f"inst-{next(_ids)}-{secrets.token_hex(3)}")


class AgentState:
    """Everything an agent would carry in its memory/state directory."""

    def __init__(self, agent_id: str, key):
        self.agent_id = agent_id
        self.key = key
        self.seq = 0
        self.head = GENESIS
        self.cred = None

    def copy(self):
        """What a clone gets: a snapshot of the state (and whatever key.copy() yields)."""
        c = AgentState(self.agent_id, self.key.copy())
        c.seq, c.head, c.cred = self.seq, self.head, self.cred
        return c
