from typing import Optional
from langgraph.graph import END, START, StateGraph
from vision.agent.nodes import DEFAULT_NODES, PolicyBypassError, sha256
from vision.agent.routing import (
    route_after_code,
    route_after_exec,
    route_after_policy,
    route_entry,
)
from vision.agent.state import AgentState

NODES = ["plan", "code", "policy_gate", "execute", "reflect", "finalize"]

CONDITIONAL = {
    START: {"plan", "code"},
    "code": {"policy_gate", "reflect", "finalize"},
    "policy_gate": {"execute", "reflect", "finalize"},
    "execute": {"reflect", "finalize"},
}

STATIC = {
    ("plan", "code"),
    ("reflect", "code"),
    ("finalize", END),
}

DEFAULT_ROUTES = {
    START: route_entry,
    "code": route_after_code,
    "policy_gate": route_after_policy,
    "execute": route_after_exec,
}


def inbound(node: str) -> set[str]:
    ins = {src for src, dsts in CONDITIONAL.items() if node in dsts}
    ins |= {src for src, dst in STATIC if dst == node}
    return ins


def build_graph(nodes: Optional[dict] = None, routes: Optional[dict] = None, hitl: bool = False):
    node_map = {**DEFAULT_NODES, **(nodes or {})}
    route_map = {**DEFAULT_ROUTES, **(routes or {})}

    b = StateGraph(AgentState)
    for name in NODES:
        b.add_node(name, node_map[name])
    for src, dsts in CONDITIONAL.items():
        b.add_conditional_edges(src, route_map[src], {d: d for d in dsts})
    for src, dst in STATIC:
        b.add_edge(src, dst)

    if hitl:
        from langgraph.checkpoint.memory import InMemorySaver
        return b.compile(checkpointer=InMemorySaver(), interrupt_before=["execute"])
    return b.compile()


def export_mermaid() -> str:
    app = build_graph()
    return app.get_graph().draw_mermaid()
