import os
import pathlib
import uuid
from typing import Optional
from vision.contracts import EventType
from vision.events import BUS, JsonlSink, emit, emit_error
from vision.agent.graph import build_graph


def solve(
    task: str,
    config: Optional[dict] = None,
    nodes: Optional[dict] = None,
    routes: Optional[dict] = None,
) -> dict:
    cfg = {
        "max_iters": int(os.environ.get("GC_MAX_ITERS", "5")),
        "policy_version": os.environ.get("GC_POLICY_VERSION", "v3"),
        "timeout_s": float(os.environ.get("GC_TIMEOUT_S", "10")),
        "use_planner": os.environ.get("GC_USE_PLANNER", "true").lower() == "true",
        "use_reflector": os.environ.get("GC_USE_REFLECTOR", "true").lower() == "true",
        "harness": None,
        **(config or {}),
    }

    run_id = cfg.get("run_id") or f"run_{uuid.uuid4().hex[:10]}"
    runs_dir = pathlib.Path(os.environ.get("GC_RUNS_DIR", "./runs"))
    events_path = runs_dir / run_id / "events.jsonl"
    sink = JsonlSink(events_path)
    BUS.subscribe(sink)

    state = {
        "run_id": run_id,
        "task": task,
        "config": cfg,
        "plan": None,
        "code": None,
        "last_code_sha": None,
        "repeats": 0,
        "approved_sha256": None,
        "policy": None,
        "sandbox": None,
        "feedback": None,
        "iteration": 0,
        "history": [],
        "status": "running",
    }

    app = build_graph(nodes=nodes, routes=routes, hitl=cfg.get("hitl", False))
    invoke_cfg = {"recursion_limit": 6 * cfg["max_iters"] + 10}
    if cfg.get("hitl"):
        invoke_cfg["configurable"] = {"thread_id": run_id}

    safe_cfg = {k: v for k, v in cfg.items()
                if not callable(v) and k not in ("llm_override", "api_key")}

    emit(run_id, EventType.RUN_START, task=task, config=safe_cfg)
    try:
        final = app.invoke(state, config=invoke_cfg)
        return {**final, "events_path": str(events_path)}
    except Exception as e:
        emit_error(run_id, e)
        emit(run_id, EventType.RUN_END, status="failed", error=str(e))
        return {**state, "status": "failed", "events_path": str(events_path)}
    finally:
        BUS.unsubscribe(sink)
