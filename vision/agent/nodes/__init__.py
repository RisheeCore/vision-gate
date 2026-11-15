import hashlib
from typing import Callable, Optional
from vision.contracts import EventType
from vision.events import emit, traced
from vision.policy import engine as policy_engine
from vision.sandbox import runner as sandbox_runner
from vision.agent.llm import get_llm, stream_and_collect
from vision.agent.prompts import (
    PLANNER_SYSTEM_PROMPT,
    REFLECTOR_SYSTEM_PROMPT,
    build_coder_messages,
    extract_first_python_block,
    sanitize_and_delimit_output,
)
from vision.agent.routing import exec_ok


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class PolicyBypassError(RuntimeError):
    """Raised when execute_node is invoked without matching approved_sha256."""


@traced("plan")
def plan_node(state: dict) -> dict:
    try:
        llm = get_llm("planner", state["config"])
        msgs = [("system", PLANNER_SYSTEM_PROMPT), ("user", state["task"])]
        plan_text = stream_and_collect(state["run_id"], "planner", llm, msgs)
        return {"plan": plan_text.strip()}
    except Exception:
        return {"plan": ""}


@traced("code")
def code_node(state: dict) -> dict:
    run_id = state["run_id"]
    next_iter = state.get("iteration", 0) + 1
    emit(run_id, EventType.ITER_START, iteration=next_iter)

    llm = get_llm("coder", state["config"])
    msgs = build_coder_messages(state)
    text = stream_and_collect(run_id, "coder", llm, msgs)
    code = extract_first_python_block(text)
    sha = sha256(code) if code else None
    repeats = state.get("repeats", 0) + 1 if (sha and sha == state.get("last_code_sha")) else 0

    return {
        "code": code,
        "last_code_sha": sha or state.get("last_code_sha"),
        "repeats": repeats,
        "iteration": next_iter,
        "policy": None,
        "sandbox": None,
        "approved_sha256": None,
        "feedback": None,
    }


@traced("policy_gate")
def policy_gate_node(state: dict) -> dict:
    code = state.get("code") or ""
    version = state["config"].get("policy_version", "v3")
    checker = state["config"].get("policy_fn") or policy_engine.check
    res = checker(code, version)
    allowed = res.decision == "ALLOW"
    dump = res.model_dump(mode="json")
    emit(state["run_id"], EventType.POLICY_RESULT, **dump)
    return {
        "policy": dump,
        "approved_sha256": sha256(code) if allowed else None,
        "feedback": None if allowed else policy_engine.format_policy_feedback(res),
    }


@traced("execute")
def execute_node(state: dict, sandbox_fn: Optional[Callable] = None) -> dict:
    code = state.get("code")
    if not code or state.get("approved_sha256") != sha256(code):
        raise PolicyBypassError("execute reached without matching policy approval")

    harness = state["config"].get("harness") or ""
    full = code + ("\n" + harness if harness else "")
    runner = sandbox_fn or state["config"].get("sandbox_fn") or sandbox_runner.run

    emit(state["run_id"], EventType.SANDBOX_START, iteration=state.get("iteration", 0))
    result = runner(full, timeout_s=state["config"].get("timeout_s", 10.0))
    dump = result.model_dump(mode="json")
    emit(state["run_id"], EventType.SANDBOX_RESULT, **dump)
    return {"sandbox": dump}


@traced("reflect")
def reflect_node(state: dict) -> dict:
    run_id = state["run_id"]
    code = state.get("code")
    pol = state.get("policy")
    sb = state.get("sandbox")

    if not code:
        fb = "No valid ```python code block was found in your response. Return exactly one ```python block."
        outcome = "no_code_block"
    elif pol and pol.get("decision") == "BLOCK":
        fb = state.get("feedback") or "Policy blocked the generated code."
        outcome = f"policy_block:{pol.get('rule_id')}"
    elif sb:
        raw_fb = sanitize_and_delimit_output(sb.get("stdout", ""), sb.get("stderr", ""))
        outcome = f"sandbox_fail:exit={sb.get('exit_code')}"
        if state["config"].get("use_reflector", True):
            try:
                llm = get_llm("reflector", state["config"])
                msgs = [
                    ("system", REFLECTOR_SYSTEM_PROMPT),
                    ("user", f"Previous code:\n```python\n{code}\n```\n\n{raw_fb}"),
                ]
                diag = stream_and_collect(run_id, "reflector", llm, msgs).strip()
                fb = f"{raw_fb}\n\nDebugger Diagnosis:\n{diag}"
            except Exception:
                fb = raw_fb
        else:
            fb = raw_fb
    else:
        fb = "Execution did not succeed. Please revise."
        outcome = "unknown_failure"

    emit(run_id, EventType.FEEDBACK, outcome=outcome, feedback=fb)
    hist_entry = {
        "iter": state.get("iteration", 0),
        "code_sha": state.get("last_code_sha"),
        "outcome": outcome,
        "feedback": fb,
    }
    return {"feedback": fb, "history": [hist_entry]}


@traced("finalize")
def finalize_node(state: dict) -> dict:
    pol = state.get("policy")
    sb = state.get("sandbox")
    success = bool(pol and pol.get("decision") == "ALLOW" and exec_ok(sb))
    status = "success" if success else "failed"
    emit(
        state["run_id"],
        EventType.RUN_END,
        status=status,
        iterations=state.get("iteration", 0),
    )
    return {"status": status}


DEFAULT_NODES = {
    "plan": plan_node,
    "code": code_node,
    "policy_gate": policy_gate_node,
    "execute": execute_node,
    "reflect": reflect_node,
    "finalize": finalize_node,
}
