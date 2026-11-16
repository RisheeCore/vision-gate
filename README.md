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

Escapes are measured, not assumed: each bypassed record is executed under \`strict_canary\` (host-networked so the canary port is reachable) with a live \`CanaryMonitor\`; a touch means the payload reached the host. At v0 the gate passes 59.3% of the corpus, Layer 2 contains 248 of those, and 27 reach the canary. At v3 the gate closes all 464 and the sandbox is never invoked. The 27 is the reason Layer 2 exists.
