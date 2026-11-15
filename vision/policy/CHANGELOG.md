# Policy Engine Changelog

- **v0 (Baseline)**: Minimal naive blocklist (`subprocess`/`socket` direct imports, `eval`/`exec` direct calls, `os.system`/`os.popen`, literal `rmtree('/')`, shell string signatures R18).
- **v1 (Import & Reference Hardening)**: Added default-deny import allowlist + alias resolution (R01), reference-level dangerous builtins (R02), full process spawn blocking (R04), network call patterns (R07), dynamic import module blocks (R16).
- **v2 (Reflection, Path & Introspection)**: Added dunder/reflection & non-literal `getattr` blocking (R03), full destructive path resolution (R05), traversal & sensitive file reads (R06), deserialization blocks (R10), interpreter introspection blocks (R11), `os.environ` secret protection (R12), and write-mode path checks (R17).
- **v3 (Resource & Concurrency Guards)**: Added infinite-loop warnings (R08), constant-folded memory/range bomb blocks (R09), multiprocessing blocks (R13), and strict AST depth/node count guards (R15).
