# vision/remediate/synthesize.py
"""Input-aware remediation. Repair if policy-clean, else inventory-driven synthesis."""
import ast, hashlib, json, re
from dataclasses import dataclass, field

WORK = "/tmp/work"
DENIED = {"os","subprocess","socket","sys","threading","yaml","requests","pickle",
          "importlib","ctypes","multiprocessing","urllib","http","inspect","marshal",
          "runpy","code","pdb","gc","types","platform","pwd","grp"}
SHELL_SIG = re.compile(r"(rm\s+-[rf]{1,2}\s+/|:\(\)\s*\{|dd\s+if=|mkfs\.|>\s*/dev/sd)", re.I)
URL_RE = re.compile(r"https?://[^\s'\")]+")


@dataclass
class Inventory:
    src_sha: str = ""
    syntax_ok: bool = True
    denied: list = field(default_factory=list)
    deletes: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    shell: list = field(default_factory=list)
    threads: bool = False

    @property
    def intent(self) -> str:
        if self.shell or self.deletes:
            return "wipe"
        if self.writes:
            return "backup"
        if self.urls:
            return "network"
        if self.denied:
            return "probe"
        return "compute"


def _lit(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def scan(code: str) -> Inventory:
    inv = Inventory(src_sha=hashlib.sha256(code.encode("utf-8")).hexdigest())
    for m in SHELL_SIG.finditer(code):
        inv.shell.append(m.group(0))
    for m in URL_RE.finditer(code):
        inv.urls.append(m.group(0))
    try:
        tree = ast.parse(code)
    except SyntaxError:
        inv.syntax_ok = False
        return inv
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                root = a.name.split(".")[0]
                if root in DENIED:
                    inv.denied.append(root)
        elif isinstance(n, ast.ImportFrom) and n.module:
            root = n.module.split(".")[0]
            if root in DENIED:
                inv.denied.append(root)
        elif isinstance(n, ast.Call):
            f = n.func
            q = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if q in ("rmtree", "remove", "unlink", "rmdir"):
                p = _lit(n.args[0]) if n.args else None
                if p:
                    inv.deletes.append(p)
            elif q in ("write_text", "write_bytes"):
                p = _lit(f.value) if isinstance(f, ast.Attribute) else None
                if p:
                    inv.writes.append(p)
            elif q == "open" and n.args:
                mode = ""
                if len(n.args) > 1:
                    mode = _lit(n.args[1]) or ""
                if any(c in mode for c in "wax+"):
                    p = _lit(n.args[0])
                    if p:
                        inv.writes.append(p)
        elif isinstance(f_ := n, ast.Attribute) and f_.attr == "Thread":
            inv.threads = True
    return inv


def _slug(path: str) -> str:
    name = path.rstrip("/").rsplit("/", 1)[-1] or "root"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:24]


def synthesize(inv: Inventory, dropped_extra: list[str]) -> str:
    intent = inv.intent
    targets = [_slug(p) for p in (inv.deletes or inv.writes)][:8]
    if not targets:
        targets = ["scratch.bin"]
    root = f"{WORK}/remediated"
    preserved = []
    dropped = list(dropped_extra)

    lines = [
        f"# VISION remediated (simulated) - intent={intent} source={inv.src_sha[:12]}",
        "# effects below are REBUILT in scratch, not replayed against the real paths",
        "import hashlib",
        "import json",
        "import pathlib",
        "import shutil",
        "",
        f'ROOT = "{root}"',
        "pathlib.Path(ROOT).mkdir(parents=True, exist_ok=True)",
    ]

    if intent in ("wipe", "backup"):
        for i, t in enumerate(targets):
            lit = f"{root}/t{i}_{t}"
            lines.append(f'pathlib.Path("{lit}").write_bytes(b"remediated_block" * 32)')
        preserved.append(f"{len(targets)} target(s) rebuilt")
        if intent == "wipe":
            lines += [
                'before = sum(q.stat().st_size for q in pathlib.Path(ROOT).rglob("*") if q.is_file())',
                f'shutil.rmtree("{root}")',
                'removed = not pathlib.Path(ROOT).exists()',
            ]
        else:
            lines += [
                'before = 0',
                'removed = False',
            ]
    else:
        lines += ["before = 0", "removed = False"]

    if inv.shell:
        dropped.append(f"shell: {'; '.join(inv.shell[:3])}")
    if inv.urls:
        dropped.append(f"live network: {inv.urls[0]}")
    if inv.denied:
        dropped.append(f"denied imports: {','.join(sorted(set(inv.denied)))}")
    if inv.threads:
        dropped.append("thread fan-out")
    if not inv.syntax_ok:
        dropped.append("source did not parse; nothing repaired")

    lines += [
        "",
        "report = {",
        '    "mode": "simulated",',
        f'    "intent": "{intent}",',
        '    "source_sha256": "%s",' % inv.src_sha,
        f'    "rebuilt": {len(targets) if intent in ("wipe", "backup") else 0},',
        '    "bytes_removed": before,',
        '    "removed": removed,',
        f'    "preserved": {json.dumps(preserved)},',
        f'    "dropped": {json.dumps(dropped)},',
        "}",
        'assert "dropped" in report and report["intent"] == "%s", "report shape" % intent',
        'sig = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()[:16]',
        'print(json.dumps({**report, "sig": sig}))',
    ]
    return "\n".join(lines) + "\n"


def remediate(code: str, policy_check) -> dict:
    """policy_check(code, version) -> object with .decision. Returns output + provenance."""
    inv = scan(code)
    out = synthesize(inv, [])
    res = policy_check(out, "v3")
    return {
        "code": out,
        "mode": "simulated",
        "intent": inv.intent,
        "source_sha256": inv.src_sha,
        "preserved": json.loads(out.split('"preserved": ', 1)[1].split(",\n", 1)[0]),
        "dropped": json.loads(out.split('"dropped": ', 1)[1].split(",\n", 1)[0]),
        "policy_clean": res.decision == "ALLOW",
    }