from mcp.server.fastmcp import FastMCP
from vision.agent.driver import solve
from vision.contracts import EventType
from vision.events import emit
from vision.policy import engine as policy_engine
from vision.sandbox import runner as sandbox_runner

mcp = FastMCP("VISION-Safety-Gate")


@mcp.tool()
def vision_policy_check(code: str, version: str = "v3") -> dict:
    """Run VISION deterministic AST static policy checks (R00-R18) on Python code before execution."""
    res = policy_engine.check(code, version).model_dump(mode="json")
    emit("ide_mcp", EventType.POLICY_RESULT, **res)
    return res


@mcp.tool()
def vision_sandbox_exec(code: str, timeout_s: float = 10.0) -> dict:
    """Gate Python code through AST policy v3 and execute inside an isolated --network none Docker sandbox."""
    pol = policy_engine.check(code, "v3")
    pol_dump = pol.model_dump(mode="json")
    emit("ide_mcp", EventType.POLICY_RESULT, **pol_dump)
    if pol.decision != "ALLOW":
        return {"blocked": True, "policy": pol_dump}
    sb = sandbox_runner.run(code, timeout_s=timeout_s, profile="strict")
    sb_dump = sb.model_dump(mode="json")
    emit("ide_mcp", EventType.SANDBOX_RESULT, **sb_dump)
    return {"blocked": False, "policy": pol_dump, "sandbox": sb_dump}


@mcp.tool()
def vision_solve_task(task: str) -> dict:
    """Generate, AST-verify, self-heal, and sandbox-test a Python solution for a coding task."""
    return solve(task, config={"policy_version": "v3", "use_planner": False, "use_reflector": False})


if __name__ == "__main__":
    mcp.run()
