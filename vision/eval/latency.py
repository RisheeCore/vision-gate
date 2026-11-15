import statistics
import time
from vision.policy import engine as policy_engine
from vision.sandbox import runner as sandbox_runner

SAMPLE_200_LINES = "\n".join(
    ["import math, json, collections"]
    + [f"def helper_{i}(x):\n    return math.sqrt(abs(x) + {i})" for i in range(65)]
    + ["print(helper_0(16))"]
)


def measure_latency(n_policy: int = 50, n_sandbox: int = 5, run_docker: bool = False) -> dict:
    pol_times: list[float] = []
    for _ in range(n_policy):
        res = policy_engine.check(SAMPLE_200_LINES, "v3")
        pol_times.append(res.duration_ms)

    sb_times: list[float] = []
    if run_docker:
        for _ in range(n_sandbox):
            t0 = time.perf_counter()
            sandbox_runner.run("print('ok')", timeout_s=5.0)
            sb_times.append((time.perf_counter() - t0) * 1000.0)

    pol_sorted = sorted(pol_times)
    p95_idx = max(0, int(0.95 * len(pol_sorted)) - 1)
    return {
        "policy_median_ms": round(statistics.median(pol_times), 3),
        "policy_p95_ms": round(pol_sorted[p95_idx], 3),
        "sandbox_median_ms": round(statistics.median(sb_times), 2) if sb_times else None,
    }
