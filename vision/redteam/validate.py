import pathlib
from vision.contracts import AttackRecord
from vision.redteam.goals import compose_reference_script
from vision.redteam.mutators import HELDOUT_MUTATORS, MUTATORS, apply_mutator
from vision.sandbox.runner import run as sandbox_run


def validate_record(rec: AttackRecord, timeout_s: float = 5.0) -> bool:
    script = compose_reference_script(rec.code, rec.goal_marker)
    res = sandbox_run(script, timeout_s=timeout_s, profile="permissive_reference")
    return "GOAL_ACHIEVED" in res.stdout or res.timed_out or res.oom_killed


def generate_mutations(records: list[AttackRecord]) -> list[AttackRecord]:
    out: list[AttackRecord] = list(records)
    counter = 1
    for rec in records:
        if rec.label != "malicious" or rec.source != "seed":
            continue
        for mid in sorted(MUTATORS.keys()):
            if mid in HELDOUT_MUTATORS and rec.split != "heldout":
                continue
            mutated_code = apply_mutator(mid, rec.code)
            out.append(
                AttackRecord(
                    id=f"{rec.id}_{mid.lower()}_{counter:04d}",
                    family_id=rec.family_id,
                    label="malicious",
                    category="obfuscated",
                    subcategory=f"{rec.category}_{mid}",
                    code=mutated_code,
                    source="mutator",
                    mutator=mid,
                    parent_id=rec.id,
                    split=rec.split,
                    goal_marker=rec.goal_marker,
                    round_created=rec.round_created,
                    notes=f"Mutated from {rec.id} via {mid}",
                )
            )
            counter += 1
    out.sort(key=lambda r: r.id)
    return out


def mutate_corpus_file(path: pathlib.Path) -> int:
    recs = [AttackRecord.model_validate_json(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    seeds_only = [r for r in recs if r.source in {"seed", "human"}]
    expanded = generate_mutations(seeds_only)
    path.write_text("\n".join(r.model_dump_json() for r in expanded) + "\n", encoding="utf-8")
    return len(expanded)
