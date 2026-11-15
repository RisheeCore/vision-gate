import importlib

import pytest

MODULES = [
    "vision", "vision.contracts", "vision.events", "vision.policy.engine",
    "vision.policy.rules", "vision.sandbox.runner", "vision.sandbox.profiles",
    "vision.sandbox.canary", "vision.agent.graph", "vision.agent.driver",
    "vision.agent.llm", "vision.eval.policy_eval", "vision.eval.report",
    "vision.redteam.goals", "vision.ui.plain", "vision.ui.replay", "vision.ui.tui",
]


@pytest.mark.parametrize("mod", MODULES)
def test_imports(mod):
    importlib.import_module(mod)


def test_server_imports():
    pytest.importorskip("fastapi")
    importlib.import_module("vision.server")
