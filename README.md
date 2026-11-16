# VISION — Very Intelligent System for Inspection, Optimization and Navigation

A LangGraph multi-agent coding system with two independent safety layers:
1. **Layer 1 (AST Policy Engine):** Deterministic static analysis (`v0`..`v3`, rules `R00`..`R18`, median latency `11.65 ms`).
2. **Layer 2 (Hardened Docker Sandbox):** Ephemeral container (`--network none`, `--read-only`, `--cap-drop ALL`, `--pids-limit 64`, `--memory 256m`, `USER 65534:65534`).

## Quickstart
```fish
source .venv/bin/activate.fish
set -x PYTHONPATH .
pytest -q
python -m vision.cli run "write a function that returns the n-th prime, with asserts" --policy v3 --ui rich
python -m vision.cli replay runs/demo_selfheal/events.jsonl --ui rich
```

## Held-Out Evaluation Summary (N = 464 Malicious, 63 Benign)
# VISION Evaluation Report

| Version | Malicious N | Block Rate | 95% Wilson CI  | Sandbox Contained | Escapes       | Benign FPR |
|---------|-------------|------------|--------------- |-------------------|---------------|------------|
|    v0   |     464     | 40.7%      | [36.4%, 45.3%] | 248               | 27 (<= 0.0065) | 0.0%       |
|    v1   |     464     | 79.3%      | [75.4%, 82.8%] | 96                | 0 (<= 0.0065) | 0.0%       |
|    v2   |     464     | 96.8%      | [94.7%, 98.0%] | 15                | 0 (<= 0.0065) | 0.0%       |
|    v3   |     464     | 100.0%     | [99.2%, 100.0%]| 0                 | 0 (<= 0.0065) | 0.0%       |

Escapes are measured, not assumed: each bypassed record is executed under `strict_canary` (host-networked so the canary port is reachable) with a live `CanaryMonitor`; a touch means the payload reached the host. At v0 the gate passes 59.3% of the corpus, Layer 2 contains 248 of those, and 27 reach the canary. At v3 the gate closes all 464 and the sandbox is never invoked. The 27 is the reason Layer 2 exists.

## Setup

`.env` is not committed. Create one with `VENICE_API_KEY=...`.
The key is only needed for LLM-assisted repair (tier 2) and the agent tab; the AST gate, tier 1, tier 3 and the sandbox need no key.

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    docker build -t vision-sandbox:latest vision/sandbox
    PYTHONPATH=$PWD .venv/bin/uvicorn vision.server:app --port 8000

## Reproducing the held-out evaluation

The held-out corpus is kept outside the repo so it cannot leak into tuning. Rebuild it, then evaluate:

    export GC_HELDOUT_PATH=~/gc_private/attacks_heldout.jsonl
    python -m vision.cli redteam split
    python -m vision.cli redteam mutate --file data/attacks_tune.jsonl
    python -m vision.cli redteam mutate --file "$GC_HELDOUT_PATH"
    python -m vision.cli eval policy --versions v0,v1,v2,v3 --split heldout
    python -m vision.cli eval report --summary <summary.json> --out reports/

Escapes require `--network host` reachability for the canary; on a host with a default-deny firewall the bridge route is dropped, which is why `strict_canary` uses host networking.
