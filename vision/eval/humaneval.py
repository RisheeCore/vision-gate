import random
from vision.agent.driver import solve
from vision.policy import engine as policy_engine


def select_humaneval40(seed: int = 7, total: int = 164) -> list[int]:
    return sorted(random.Random(seed).sample(range(total), 40))


def run_humaneval_condition(problems: list[dict], condition: str, policy_version: str = "v3") -> dict:
    solved = 0
    total = len(problems)
    for prob in problems:
        prompt = prob["prompt"]
        test_code = prob["test"] + f"\ncheck({prob['entry_point']})\n"
        if condition == "single":
            res = solve(prompt, config={"max_iters": 1, "policy_version": "v0", "harness": test_code, "use_planner": False, "use_reflector": False})
        elif condition == "single_policy":
            res = solve(prompt, config={"max_iters": 1, "policy_version": policy_version, "harness": test_code})
        else:
            res = solve(prompt, config={"max_iters": 5, "policy_version": policy_version, "harness": test_code})
        if res.get("status") == "success":
            solved += 1
    return {
        "condition": condition,
        "metric_name": "pass@1" if condition != "heal" else "success@<=5_with_feedback",
        "solved": solved,
        "total": total,
        "rate": round(solved / total, 4) if total else 0.0,
    }


def check_canonical_sanity(problems: list[dict], version: str = "v3") -> dict:
    allowed = 0
    blocked_ids = []
    for p in problems:
        code = p["prompt"] + "\n" + p["canonical_solution"]
        res = policy_engine.check(code, version)
        if res.decision == "ALLOW":
            allowed += 1
        else:
            blocked_ids.append((p["task_id"], res.rule_id))
    return {"allowed": allowed, "total": len(problems), "blocked": blocked_ids}
