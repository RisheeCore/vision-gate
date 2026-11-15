import pytest
from langgraph.graph import END, START
from vision.agent.driver import solve
from vision.agent.graph import CONDITIONAL, NODES, STATIC, PolicyBypassError, export_mermaid, inbound
from vision.agent.llm import ScriptedLLM
from vision.agent.nodes import execute_node, sha256
from vision.agent.routing import route_after_code, route_after_exec, route_after_policy, route_entry
from vision.contracts import SandboxResult


def _ok_sandbox(code: str, timeout_s: float = 10.0) -> SandboxResult:
    return SandboxResult(stdout="ALL TESTS PASSED\n", stderr="", exit_code=0, duration_ms=5.0)


def test_tg1_topology_invariants():
    assert inbound("execute") == {"policy_gate"}
    assert inbound("policy_gate") == {"code"}
    edges = {(s, d) for s, ds in CONDITIONAL.items() for d in ds} | set(STATIC)
    seen, frontier = set(), [START]
    while frontier:
        n = frontier.pop()
        for s, d in edges:
            if s == n and d not in seen:
                seen.add(d)
                frontier.append(d)
    assert set(NODES) <= seen and END in seen


@pytest.mark.parametrize(
    "router,state,expected",
    [
        (route_entry, {"config": {"use_planner": True}}, "plan"),
        (route_entry, {"config": {"use_planner": False}}, "code"),
        (route_after_code, {"repeats": 2, "code": "x=1", "iteration": 1, "config": {"max_iters": 5}}, "finalize"),
        (route_after_code, {"repeats": 0, "code": "x=1", "iteration": 1, "config": {"max_iters": 5}}, "policy_gate"),
        (route_after_code, {"repeats": 0, "code": None, "iteration": 1, "config": {"max_iters": 5}}, "reflect"),
        (route_after_code, {"repeats": 0, "code": None, "iteration": 5, "config": {"max_iters": 5}}, "finalize"),
        (route_after_policy, {"policy": {"decision": "ALLOW"}, "iteration": 1, "config": {"max_iters": 5}}, "execute"),
        (route_after_policy, {"policy": {"decision": "BLOCK"}, "iteration": 2, "config": {"max_iters": 5}}, "reflect"),
        (route_after_policy, {"policy": {"decision": "BLOCK"}, "iteration": 5, "config": {"max_iters": 5}}, "finalize"),
        (route_after_exec, {"sandbox": {"exit_code": 0, "timed_out": False, "oom_killed": False}, "iteration": 1, "config": {"max_iters": 5}}, "finalize"),
        (route_after_exec, {"sandbox": {"exit_code": 1, "timed_out": False, "oom_killed": False}, "iteration": 1, "config": {"max_iters": 5}}, "reflect"),
        (route_after_exec, {"sandbox": {"exit_code": 1, "timed_out": False, "oom_killed": False}, "iteration": 5, "config": {"max_iters": 5}}, "finalize"),
    ],
)
def test_tg2_routing_table(router, state, expected):
    assert router(state) == expected


def test_tg3_execute_fail_closed():
    called = []
    spy = lambda code, timeout_s=10.0: called.append(code)
    with pytest.raises(PolicyBypassError):
        execute_node({"run_id": "t", "code": "print(1)", "approved_sha256": None, "config": {}}, sandbox_fn=spy)
    with pytest.raises(PolicyBypassError):
        execute_node({"run_id": "t", "code": "print(1)", "approved_sha256": sha256("other"), "config": {}}, sandbox_fn=spy)
    assert called == []


def test_tg4_scripted_recovery():
    seen_in_sandbox: list[str] = []

    def spy_sb(code: str, timeout_s: float = 10.0) -> SandboxResult:
        seen_in_sandbox.append(code)
        return _ok_sandbox(code, timeout_s)

    llm = ScriptedLLM(
        responses=[
            "Plan: write code",
            "```python\nimport shutil\nshutil.rmtree('/')\n```",
            "```python\nprint('ALL TESTS PASSED')\n```",
        ]
    )
    res = solve("clean files", config={"llm_override": llm, "sandbox_fn": spy_sb, "max_iters": 5})
    assert res["status"] == "success"
    assert res["iteration"] == 2
    assert len(seen_in_sandbox) == 1
    assert "rmtree" not in seen_in_sandbox[0]


def test_tg5_syntax_error_recovery():
    llm = ScriptedLLM(
        responses=[
            "```python\ndef broken(:\n```",
            "```python\nprint('ALL TESTS PASSED')\n```",
        ]
    )
    res = solve("task", config={"llm_override": llm, "sandbox_fn": _ok_sandbox, "use_planner": False})
    assert res["status"] == "success"
    assert res["iteration"] == 2


def test_tg6_no_code_block_retry():
    llm = ScriptedLLM(
        responses=[
            "I forgot to use a fenced block.",
            "```python\nprint('ALL TESTS PASSED')\n```",
        ]
    )
    res = solve("task", config={"llm_override": llm, "sandbox_fn": _ok_sandbox, "use_planner": False})
    assert res["status"] == "success"


def test_tg7_repeated_code_terminates():
    llm = ScriptedLLM(
        responses=[
            "```python\nimport subprocess\n```",
            "```python\nimport subprocess\n```",
            "```python\nimport subprocess\n```",
        ]
    )
    res = solve("task", config={"llm_override": llm, "sandbox_fn": _ok_sandbox, "use_planner": False, "max_iters": 5})
    assert res["status"] == "failed"
    assert res["iteration"] <= 3


def test_tg8_budget_exhausted():
    llm = ScriptedLLM(responses=[f"```python\nimport subprocess # {i}\n```" for i in range(10)])
    res = solve("task", config={"llm_override": llm, "sandbox_fn": _ok_sandbox, "use_planner": False, "max_iters": 5})
    assert res["status"] == "failed"
    assert res["iteration"] == 5


def test_tg9_sandbox_exception_fails_closed():
    def raising_sb(code: str, timeout_s: float = 10.0):
        raise RuntimeError("Docker daemon unreachable")

    llm = ScriptedLLM(responses=["```python\nprint(1)\n```"])
    res = solve("task", config={"llm_override": llm, "sandbox_fn": raising_sb, "use_planner": False})
    assert res["status"] == "failed"


def test_tg10_mermaid_export():
    mmd = export_mermaid()
    for n in NODES:
        assert n in mmd


def test_tg11_no_stale_state():
    calls = 0

    def fail_then_block_sb(code: str, timeout_s: float = 10.0) -> SandboxResult:
        nonlocal calls
        calls += 1
        return SandboxResult(stdout="ok", stderr="", exit_code=0, duration_ms=1.0)

    llm = ScriptedLLM(responses=["```python\nprint('ok')\n```"])
    res = solve("task", config={"llm_override": llm, "sandbox_fn": fail_then_block_sb, "use_planner": False})
    assert res["status"] == "success"
    assert calls == 1


def test_tg12_ablation_flags():
    coder_llm = ScriptedLLM(responses=["```python\nx = 1\n```", "```python\nx = 2\n```"])
    reflector_llm = ScriptedLLM(responses=["Diagnosis"])

    def fail_once_sb(code: str, timeout_s: float = 10.0) -> SandboxResult:
        if "x = 1" in code:
            return SandboxResult(stdout="", stderr="AssertionError", exit_code=1, duration_ms=2.0)
        return _ok_sandbox(code, timeout_s)

    res = solve(
        "task",
        config={
            "llm_override": {"coder": coder_llm, "reflector": reflector_llm, "planner": reflector_llm},
            "sandbox_fn": fail_once_sb,
            "use_planner": False,
            "use_reflector": False,
        },
    )
    assert res["status"] == "success"
    assert len(reflector_llm.calls) == 0
