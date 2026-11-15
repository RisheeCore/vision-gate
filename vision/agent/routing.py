def budget_left(s: dict) -> bool:
    return s["iteration"] < s["config"]["max_iters"]


def exec_ok(sb: dict | None) -> bool:
    return (
        bool(sb)
        and sb["exit_code"] == 0
        and not sb.get("timed_out", False)
        and not sb.get("oom_killed", False)
    )


def route_entry(s: dict) -> str:
    return "plan" if s["config"].get("use_planner", True) else "code"


def route_after_code(s: dict) -> str:
    if s.get("repeats", 0) >= 2:
        return "finalize"
    if s.get("code"):
        return "policy_gate"
    return "reflect" if budget_left(s) else "finalize"


def route_after_policy(s: dict) -> str:
    if s["policy"]["decision"] == "ALLOW":
        return "execute"
    return "reflect" if budget_left(s) else "finalize"


def route_after_exec(s: dict) -> str:
    if exec_ok(s.get("sandbox")):
        return "finalize"
    return "reflect" if budget_left(s) else "finalize"
