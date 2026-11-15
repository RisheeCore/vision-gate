import ast
from vision.agent.llm import ScriptedLLM
from vision.contracts import AttackRecord, SandboxResult
from vision.redteam.attack_graph import build_attack_graph
from vision.redteam.mutators import MUTATORS, apply_mutator
from vision.redteam.split import assign_split
from vision.redteam.validate import generate_mutations


def test_all_15_mutators_produce_valid_python_syntax():
    seed = "import os\nx = 1 + 1"
    for mid in MUTATORS:
        mutated = apply_mutator(mid, seed)
        ast.parse(mutated)


def test_family_split_and_heldout_mutator_isolation():
    r_tune = AttackRecord(
        id="a_1", family_id="fam_tune", label="malicious", category="destructive",
        code="import os", source="seed", split="tune",
    )
    r_held = AttackRecord(
        id="a_2", family_id="fam_held", label="malicious", category="destructive",
        code="import os", source="seed", split="heldout",
    )
    muts = generate_mutations([r_tune, r_held])
    tune_mutators = {m.mutator for m in muts if m.split == "tune" and m.mutator}
    held_mutators = {m.mutator for m in muts if m.split == "heldout" and m.mutator}
    assert {"M13", "M14", "M15"}.isdisjoint(tune_mutators)
    assert {"M13", "M14", "M15"}.issubset(held_mutators)
    assert assign_split("fam_123") == assign_split("fam_123")


def test_attack_graph_loop():
    llm = ScriptedLLM(
        responses=[
            "```python\nimport subprocess\n```",
            "```python\nprint('GOAL_ACHIEVED')\n```",
        ]
    )
    fake_sb = lambda code, timeout_s=5.0, profile="strict": SandboxResult(
        stdout="GOAL_ACHIEVED\n", stderr="", exit_code=0, duration_ms=1.0, canary_touched=False
    )
    app = build_attack_graph()
    out = app.invoke(
        {
            "category": "destructive",
            "policy_version": "v3",
            "max_attempts": 3,
            "attempts": 0,
            "last_code": None,
            "syntax_ok": False,
            "last_verdict": None,
            "allowed": False,
            "valid_payload": False,
            "outcome": None,
            "config": {"llm_override": llm, "sandbox_fn": fake_sb},
        }
    )
    assert out["attempts"] == 2
    assert out["outcome"] == "SANDBOX_CONTAINED"
