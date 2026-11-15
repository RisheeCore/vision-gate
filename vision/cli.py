import argparse
import json
import os
import pathlib
import sys
import pytest
from vision.agent.driver import solve
from vision.agent.graph import export_mermaid
from vision.contracts import AttackRecord
from vision.eval.latency import measure_latency
from vision.eval.policy_eval import evaluate_corpus
from vision.eval.report import generate_reports
from vision.events import BUS
from vision.policy import engine as policy_engine
from vision.redteam.split import split_corpus
from vision.redteam.validate import mutate_corpus_file, validate_record
from vision.ui.plain import PlainSink
from vision.ui.replay import replay_events
from vision.ui.tui import RichSink


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vision", description="VISION CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sb = sub.add_parser("sandbox")
    p_sb.add_argument("action", choices=["selftest", "build"])

    p_pol = sub.add_parser("policy")
    pol_sub = p_pol.add_subparsers(dest="pol_cmd", required=True)
    p_pchk = pol_sub.add_parser("check")
    p_pchk.add_argument("file")
    p_pchk.add_argument("--version", default="v3")
    pol_sub.add_parser("test")

    p_run = sub.add_parser("run")
    p_run.add_argument("task")
    p_run.add_argument("--policy", default="v3")
    p_run.add_argument("--provider", default="ollama")
    p_run.add_argument("--max-iters", type=int, default=5)
    p_run.add_argument("--ui", choices=["rich", "plain"], default="plain")
    p_run.add_argument("--no-planner", action="store_true")
    p_run.add_argument("--no-reflector", action="store_true")

    p_gr = sub.add_parser("graph")
    p_gr.add_argument("action", choices=["export"])
    p_gr.add_argument("--out", default="docs/graph.mmd")

    p_rep = sub.add_parser("replay")
    p_rep.add_argument("events_file")
    p_rep.add_argument("--speed", type=float, default=2.0)
    p_rep.add_argument("--ui", choices=["rich", "plain"], default="rich")

    p_rt = sub.add_parser("redteam")
    rt_sub = p_rt.add_subparsers(dest="rt_cmd", required=True)
    rt_split = rt_sub.add_parser("split")
    rt_split.add_argument("--seeds", default="data/seeds.jsonl")
    rt_mut = rt_sub.add_parser("mutate")
    rt_mut.add_argument("--file", default="data/attacks_tune.jsonl")
    rt_val = rt_sub.add_parser("validate")
    rt_val.add_argument("--file", default="data/attacks_tune.jsonl")

    p_ev = sub.add_parser("eval")
    ev_sub = p_ev.add_subparsers(dest="ev_cmd", required=True)
    ev_pol = ev_sub.add_parser("policy")
    ev_pol.add_argument("--versions", default="v0,v1,v2,v3")
    ev_pol.add_argument("--split", choices=["tune", "heldout"], default="tune")
    ev_pol.add_argument("--no-sandbox", action="store_true")
    ev_lat = ev_sub.add_parser("latency")
    ev_lat.add_argument("--docker", action="store_true")
    ev_rep = ev_sub.add_parser("report")
    ev_rep.add_argument("--summary", required=True)
    ev_rep.add_argument("--out", default="reports/")

    args = parser.parse_args(argv)

    if args.cmd == "sandbox" and args.action == "build":
        import subprocess as _sp
        _img = os.environ.get("GC_SANDBOX_IMAGE", "vision-sandbox:latest")
        return _sp.call(["docker", "build", "-t", _img, "vision/sandbox"])

    if args.cmd == "sandbox" and args.action == "selftest":
        return pytest.main(["tests/sandbox", "-q"])

    if args.cmd == "policy":
        if args.pol_cmd == "test":
            return pytest.main(["tests/policy", "-q"])
        code = pathlib.Path(args.file).read_text(encoding="utf-8")
        res = policy_engine.check(code, args.version)
        print(res.model_dump_json(indent=2))
        return 0 if res.decision == "ALLOW" else 1

    if args.cmd == "graph" and args.action == "export":
        mmd = export_mermaid()
        out_p = pathlib.Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(mmd, encoding="utf-8")
        print(f"Exported Mermaid graph to {out_p}")
        return 0

    if args.cmd == "replay":
        count = replay_events(pathlib.Path(args.events_file), speed=args.speed, ui=args.ui)
        print(f"Replayed {count} events.")
        return 0

    if args.cmd == "run":
        sink = RichSink() if args.ui == "rich" else PlainSink()
        BUS.subscribe(sink)
        if isinstance(sink, RichSink):
            sink.start()
        try:
            res = solve(
                args.task,
                config={
                    "policy_version": args.policy,
                    "max_iters": args.max_iters,
                    "use_planner": not args.no_planner,
                    "use_reflector": not args.no_reflector,
                },
            )
        finally:
            if isinstance(sink, RichSink):
                sink.stop()
            BUS.unsubscribe(sink)
        print(f"Run finished with status={res['status']} events={res.get('events_path')}")
        return 0 if res["status"] == "success" else 1

    if args.cmd == "redteam":
        if args.rt_cmd == "split":
            held_path = pathlib.Path(os.environ.get("GC_HELDOUT_PATH", "~/gc_private/attacks_heldout.jsonl"))
            counts = split_corpus(
                pathlib.Path(args.seeds),
                pathlib.Path("data/attacks_tune.jsonl"),
                held_path,
                pathlib.Path("data/HELDOUT.sha256"),
            )
            print(json.dumps(counts, indent=2))
            return 0
        if args.rt_cmd == "mutate":
            total = mutate_corpus_file(pathlib.Path(args.file))
            print(f"Expanded corpus to {total} records.")
            return 0
        if args.rt_cmd == "validate":
            recs = [AttackRecord.model_validate_json(ln) for ln in pathlib.Path(args.file).read_text().splitlines() if ln.strip()]
            valid_n = sum(1 for r in recs if validate_record(r))
            print(f"Valid records: {valid_n}/{len(recs)}")
            return 0

    if args.cmd == "eval":
        if args.ev_cmd == "policy":
            versions = [v.strip() for v in args.versions.split(",") if v.strip()]
            attack_file = (
                pathlib.Path("data/attacks_tune.jsonl")
                if args.split == "tune"
                else pathlib.Path(os.environ.get("GC_HELDOUT_PATH", "~/gc_private/attacks_heldout.jsonl")).expanduser()
            )
            recs = [AttackRecord.model_validate_json(ln) for ln in attack_file.read_text().splitlines() if ln.strip()]
            benign_file = pathlib.Path("data/benign.jsonl")
            if benign_file.exists():
                recs.extend(AttackRecord.model_validate_json(ln) for ln in benign_file.read_text().splitlines() if ln.strip())
            out = evaluate_corpus(recs, versions, run_sandbox_on_bypass=not args.no_sandbox)
            print(json.dumps(out, indent=2))
            return 0
        if args.ev_cmd == "latency":
            print(json.dumps(measure_latency(run_docker=args.docker), indent=2))
            return 0
        if args.ev_cmd == "report":
            files = generate_reports(pathlib.Path(args.summary), pathlib.Path(args.out))
            print("Generated:", files)
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
