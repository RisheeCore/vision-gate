import ast
import pathlib
import time
import yaml
from vision.contracts import Decision, Finding, PolicyResult
from vision.policy.aliases import build_context
from vision.policy.rules import REGISTRY

MAX_SOURCE_BYTES = 20_000
_VERSIONS_CACHE: dict[str, list[str]] = {}


def _load_versions() -> dict[str, list[str]]:
    if not _VERSIONS_CACHE:
        p = pathlib.Path(__file__).with_name("versions.yaml")
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        for ver, cfg in data.get("versions", {}).items():
            _VERSIONS_CACHE[ver] = list(cfg.get("rules", []))
    return _VERSIONS_CACHE


def enabled_rules(version: str) -> list[str]:
    versions = _load_versions()
    if version not in versions:
        raise ValueError(f"Unknown policy version: {version}")
    return [r for r in versions[version] if r != "R00"]


def _block(rule_id: str, message: str, version: str, t0: float, line: int = 1) -> PolicyResult:
    dur = (time.perf_counter() - t0) * 1000.0
    finding = Finding(rule_id=rule_id, severity="BLOCK", message=message, line=line, col=0)
    return PolicyResult(
        decision=Decision.BLOCK,
        rule_id=rule_id,
        reason=message,
        line=line,
        findings=[finding],
        policy_version=version,
        duration_ms=round(dur, 3),
    )


def check(code: str, version: str = "v3") -> PolicyResult:
    t0 = time.perf_counter()
    if len(code.encode("utf-8")) > MAX_SOURCE_BYTES:
        return _block("R15", "source exceeds 20 KB size limit", version, t0)

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return _block("R00", f"syntax error: {e.msg}", version, t0, line=e.lineno or 1)
    except (RecursionError, MemoryError):
        return _block("R15", "AST too deep or large to parse", version, t0)

    ctx = build_context(tree, code)
    findings: list[Finding] = []
    for rkey in enabled_rules(version):
        rule = REGISTRY.get(rkey)
        if rule is not None:
            findings.extend(rule.check(tree, ctx))

    blocks = [f for f in findings if f.severity == "BLOCK"]
    blocks.sort(key=lambda f: (f.line if f.line is not None else 999999, f.rule_id))

    dur = (time.perf_counter() - t0) * 1000.0
    if blocks:
        primary = blocks[0]
        return PolicyResult(
            decision=Decision.BLOCK,
            rule_id=primary.rule_id,
            reason=primary.message,
            line=primary.line,
            findings=findings,
            policy_version=version,
            duration_ms=round(dur, 3),
        )

    return PolicyResult(
        decision=Decision.ALLOW,
        rule_id=None,
        reason="",
        line=None,
        findings=findings,
        policy_version=version,
        duration_ms=round(dur, 3),
    )


def format_policy_feedback(res: PolicyResult) -> str:
    line_part = f" (line {res.line})" if res.line else ""
    return (
        f"POLICY REJECTED your code (policy {res.policy_version}).\n"
        f"Rule {res.rule_id}{line_part}: {res.reason}.\n"
        "Rewrite using only paths under /tmp/work or relative paths, avoid dangerous "
        "builtins/modules, then return the full corrected program in one ```python block."
    )
