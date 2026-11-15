import json
import os
import pathlib
import time
from typing import Optional
from vision.contracts import AttackRecord, Outcome
from vision.eval.stats import family_bypass_rate, rule_of_three, wilson
from vision.policy import engine as policy_engine
from vision.sandbox import runner as sandbox_runner
from vision.redteam.goals import substitute_placeholders
from vision.sandbox.canary import CanaryMonitor


def _run_with_canary(code: str, canary_host: str):
    for port in (47001, 0):
        try:
            with CanaryMonitor(port=port) as mon:
                script = substitute_placeholders(code, "127.0.0.1", mon.port)
                return sandbox_runner.run(script, timeout_s=4.0, profile="strict_canary", canary=mon)
        except OSError:
            continue
    raise RuntimeError("no canary port available")


def evaluate_corpus(
    records: list[AttackRecord],
    versions: list[str],
    run_sandbox_on_bypass: bool = True,
    out_dir: Optional[pathlib.Path] = None,
    canary_host: str = os.environ.get("GC_CANARY_HOST", "172.17.0.1"),
) -> dict:
    out_dir = out_dir or pathlib.Path(os.environ.get("GC_RUNS_DIR", "./runs")) / "eval" / time.strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, dict] = {}
    raw_path = out_dir / "policy_eval_raw.jsonl"

    with raw_path.open("w", encoding="utf-8") as raw_f:
        for ver in versions:
            mal_total = 0
            ast_blocked = 0
            sb_contained = 0
            escaped = 0
            ben_total = 0
            fp_count = 0
            per_cat: dict[str, list[int]] = {}
            ver_rows: list[dict] = []

            for rec in records:
                pres = policy_engine.check(rec.code, ver)
                if rec.label == "malicious":
                    mal_total += 1
                    cat = rec.category
                    per_cat.setdefault(cat, [0, 0])
                    per_cat[cat][1] += 1
                    if pres.decision == "BLOCK":
                        outcome = Outcome.AST_BLOCKED.value
                        ast_blocked += 1
                        per_cat[cat][0] += 1
                    else:
                        if run_sandbox_on_bypass:
                            sb = _run_with_canary(rec.code, canary_host)
                            if sb.canary_touched:
                                outcome = Outcome.ESCAPED.value
                                escaped += 1
                            else:
                                outcome = Outcome.SANDBOX_CONTAINED.value
                                sb_contained += 1
                        else:
                            outcome = Outcome.SANDBOX_CONTAINED.value
                            sb_contained += 1
                else:
                    ben_total += 1
                    if pres.decision == "BLOCK":
                        outcome = Outcome.FALSE_POSITIVE.value
                        fp_count += 1
                    else:
                        outcome = Outcome.TRUE_NEGATIVE.value

                row = {
                    "version": ver,
                    "id": rec.id,
                    "family_id": rec.family_id,
                    "label": rec.label,
                    "category": rec.category,
                    "split": rec.split,
                    "outcome": outcome,
                    "rule_id": pres.rule_id,
                    "duration_ms": pres.duration_ms,
                }
                ver_rows.append(row)
                raw_f.write(json.dumps(row) + "\n")

            byp_fam, tot_fam, fam_rate = family_bypass_rate(ver_rows)
            summary[ver] = {
                "malicious_n": mal_total,
                "ast_blocked": ast_blocked,
                "block_rate": round(ast_blocked / mal_total, 4) if mal_total else 0.0,
                "block_ci": wilson(ast_blocked, mal_total),
                "sandbox_contained": sb_contained,
                "escaped": escaped,
                "escape_upper_bound": rule_of_three(mal_total),
                "benign_n": ben_total,
                "false_positives": fp_count,
                "fpr": round(fp_count / ben_total, 4) if ben_total else 0.0,
                "fpr_ci": wilson(fp_count, ben_total),
                "family_bypass_rate": fam_rate,
                "families_bypassed": f"{byp_fam}/{tot_fam}",
                "per_category": {
                    c: {
                        "blocked": counts[0],
                        "n": counts[1],
                        "rate": round(counts[0] / counts[1], 4) if counts[1] else 0.0,
                        "ci": wilson(counts[0], counts[1]),
                    }
                    for c, counts in per_cat.items()
                },
            }

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return {"out_dir": str(out_dir), "summary": summary}
