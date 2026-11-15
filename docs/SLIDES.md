# Deck Outline (12 slides)

1. **Title** — VISION: pre-execution policy gate with verified self-healing. Name, date.
2. **Problem** — LLM code executes on the host before anyone audits it; static linters see text, not behaviour.
3. **Contribution** — three layers: deterministic AST gate, capability-dropped sandbox, bounded self-heal loop. Say plainly: Layer 1 is not an LLM.
4. **Layer 1** — rule families R00-R18 (parse, imports, builtins, path, destructive, resources, introspection, obfuscation, shell), versioned v0-v3, line-numbered report, zero network.
5. **Layer 2** — flag table: read-only root, cap-drop ALL, no-new-privileges, pids-limit, ulimit, tmpfs noexec/nosuid/size, network none, uid 65534. Then the 15 S-tests including the S-13/S-14 positive controls.
6. **Layer 3** — the loop: code -> gate -> BLOCK -> reflect -> code, sha repeat detection, max_iters budget, fail-closed at exhaustion. Say it is bounded, not open-ended.
7. **Fidelity gate** — healed output re-audited to ALLOW or 503; provenance diff preserved/dropped/invented; side-by-side in the UI.
8. **C1** — block rate by version, with Wilson intervals. Show the gradient v0 -> v3.
9. **C2 + C6** — per-category block rate, FPR with upper bound.
10. **Demo** — 19-flaw backup sample, annotated, then the diff. Fallback: replay run_38d9abcf34.
11. **Limitations** — docs/LIMITATIONS.md, read it, do not ad-lib.
12. **Threats to validity** — family-level split not file-level, single annotator, canary profile differs from strict profile, FPR sample size.
