# The Handoff Problem: Continuity-Bound Identity for Self-Cloning Agents

Apart Research Swarm Alignment Hackathon (Nov 6-8, 2026), Track 3: Strengthening Agent Infrastructure.

A valid identity proof shows that someone holds a credential, not that one agent kept running.
We test today's identity mechanisms (signed hash chains, witness counters, nonces,
short-lived credentials, hardware keys, runtime attestation) against an agent that copies
itself, and propose **Continuity-Bound Identity** (L7): instance pinning with pre-approved
succession plus a per-identity rate budget calibrated on real agent timing (AI Village).

All code in this repository was written during the hackathon weekend (Nov 7, 2026),
with AI assistance.

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m experiments.run_all --quick     # smoke test (~30 s)

# optional, real agent timing (gated dataset; accept terms on Hugging Face first)
huggingface-cli login
python -m experiments.calibrate_ai_village --inspect
python -m experiments.calibrate_ai_village

python -m experiments.run_all             # full run -> results/
```

## Layout

| file | what it is |
|---|---|
| `handoff/crypto.py` | Ed25519 signing; software / hardware / runtime-bound key models |
| `handoff/world.py` | processes (fresh instance id per launch) and agent state |
| `handoff/witness.py` | the witness and defence levels L1-L7 |
| `handoff/scenarios.py` | benign runs B0-B2 and attacks A1-A6 |
| `handoff/evasion_tax.py` | throughput of hidden copies; rate-budget trade-off |
| `experiments/run_all.py` | runs everything, writes `results/` (CSV, JSON, charts, summary.md) |
| `experiments/calibrate_ai_village.py` | extracts real per-agent action gaps from AI Village |

## Simulated vs real

Hardware keys and runtime attestation are **simulated** by the properties they enforce
(non-exportable, host-bound, per-process instance id). Results show what follows from
those properties, not the security of any specific TPM/TEE product.

## Data

AI Digest, "AI Village dataset", 2026. https://theaidigest.org/village (research terms).
