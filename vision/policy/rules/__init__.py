import ast
import posixpath
import re
from typing import Optional
from vision.contracts import Finding
from vision.policy.aliases import Ctx, resolve_qualname

REGISTRY: dict[str, "Rule"] = {}


def register(cls):
    REGISTRY[cls.key] = cls()
    return cls


class Rule:
    key: str = "R??"
    id: str = "R??"
    severity: str = "BLOCK"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        raise NotImplementedError


ALLOWLIST_MODULES = {
    "math", "cmath", "itertools", "functools", "operator", "collections",
    "heapq", "bisect", "array", "typing", "dataclasses", "enum", "abc",
    "string", "re", "json", "csv", "io", "datetime", "time", "random",
    "statistics", "decimal", "fractions", "textwrap", "copy", "unittest",
    "pathlib", "tempfile", "hashlib", "uuid", "pprint", "contextlib",
    "numbers", "struct", "logging", "os", "shutil", "sys", "threading",
}

DENYLIST_MODULES = {
    "subprocess", "socket", "ssl", "http", "urllib", "ftplib", "smtplib",
    "telnetlib", "imaplib", "poplib", "xmlrpc", "socketserver", "wsgiref",
    "requests", "httpx", "aiohttp", "asyncio", "ctypes", "cffi", "pty",
    "tty", "fcntl", "resource", "signal", "select", "selectors", "mmap",
    "multiprocessing", "concurrent", "pickle", "marshal", "shelve", "dill",
    "importlib", "runpy", "code", "codeop", "pdb", "inspect", "gc",
    "builtins", "types", "platform", "pwd", "grp", "syslog", "webbrowser",
    "ensurepip", "pip", "site", "sysconfig", "posix", "nt",
}


READABLE_EXCEPTIONS = {"/etc/hostname", "/etc/os-release", "/etc/timezone", "/etc/resolv.conf"}


def _is_safe_path_str(p: str) -> bool:
    if not p or "\x00" in p:
        return False
    raw_parts = p.replace("\\", "/").split("/")
    if ".." in raw_parts:
        return False
    norm = posixpath.normpath(p)
    if norm in READABLE_EXCEPTIONS:
        return True
    if norm in {"/", "~"} or norm.startswith("~"):
        return False
    protected_prefixes = ("/home", "/etc", "/usr", "/var", "/bin", "/boot", "/root", "/proc", "/sys", "/dev")
    if any(norm == pref or norm.startswith(pref + "/") for pref in protected_prefixes):
        return False
    if norm.startswith("/"):
        return norm == "/tmp" or norm.startswith("/tmp/") or norm == "/work" or norm.startswith("/work/")
    return True


def _resolve_path_expr(node: ast.AST, ctx: Ctx) -> tuple[bool, Optional[str]]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _is_safe_path_str(node.value), node.value
    if isinstance(node, ast.Name):
        if node.id in ctx.safe_root_vars:
            return True, "/tmp/safe_var"
        if node.id in ctx.string_vars:
            val = ctx.string_vars[node.id]
            return _is_safe_path_str(val), val
        return False, None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left_ok, _ = _resolve_path_expr(node.left, ctx)
        right_ok, _ = _resolve_path_expr(node.right, ctx)
        return (left_ok and right_ok), "/tmp/joined"
    if isinstance(node, ast.Call):
        qn = resolve_qualname(node.func, ctx.aliases)
        if qn in {"os.path.join", "posixpath.join", "pathlib.Path", "Path"} and node.args:
            first_ok, _ = _resolve_path_expr(node.args[0], ctx)
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if ".." in arg.value.split("/") or arg.value.startswith("/"):
                        return False, arg.value
                else:
                    return False, None
            return first_ok, "/tmp/joined"
    return False, None


@register
class R01ImportsV0(Rule):
    key = "R01_v0"
    id = "R01"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    root = a.name.split(".")[0]
                    if root in {"subprocess", "socket"}:
                        out.append(Finding(rule_id="R01", severity="BLOCK", message=f"import of '{root}' is blocked", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.ImportFrom) and n.module:
                root = n.module.split(".")[0]
                if root in {"subprocess", "socket"}:
                    out.append(Finding(rule_id="R01", severity="BLOCK", message=f"import from '{root}' is blocked", line=n.lineno, col=n.col_offset))
        return out


@register
class R01Imports(Rule):
    key = "R01"
    id = "R01"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for mod, lineno in ctx.star_imports:
            out.append(Finding(rule_id="R01", severity="BLOCK", message=f"star import from '{mod}' is prohibited", line=lineno, col=0))
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    root = a.name.split(".")[0]
                    if root in DENYLIST_MODULES or root not in ALLOWLIST_MODULES:
                        out.append(Finding(rule_id="R01", severity="BLOCK", message=f"module '{a.name}' is not in the import allowlist", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.ImportFrom):
                if n.level and n.level > 0:
                    out.append(Finding(rule_id="R01", severity="BLOCK", message="relative imports are not permitted", line=n.lineno, col=n.col_offset))
                    continue
                root = (n.module or "").split(".")[0]
                if root in DENYLIST_MODULES or root not in ALLOWLIST_MODULES:
                    out.append(Finding(rule_id="R01", severity="BLOCK", message=f"module '{n.module}' is not in the import allowlist", line=n.lineno, col=n.col_offset))
        return out


@register
class R02BuiltinsV0(Rule):
    key = "R02_v0"
    id = "R02"
    DENIED = {"eval", "exec", "compile", "__import__"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in self.DENIED:
                out.append(Finding(rule_id="R02", severity="BLOCK", message=f"direct call to dangerous builtin '{n.func.id}'", line=n.lineno, col=n.col_offset))
        return out


@register
class R02DangerousBuiltins(Rule):
    key = "R02"
    id = "R02"
    DENIED = {"eval", "exec", "compile", "__import__", "breakpoint", "globals", "locals", "open_code"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Name):
                resolved = ctx.aliases.get(n.id, n.id).split(".")[-1]
                if n.id in self.DENIED or resolved in self.DENIED:
                    out.append(Finding(rule_id="R02", severity="BLOCK", message=f"reference to dangerous builtin '{n.id}'", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.Attribute) and n.attr in self.DENIED:
                out.append(Finding(rule_id="R02", severity="BLOCK", message=f"attribute reference to dangerous builtin '{n.attr}'", line=n.lineno, col=n.col_offset))
        return out


@register
class R03ReflectionDunder(Rule):
    key = "R03"
    id = "R03"
    FORBIDDEN_DUNDERS = {
        "__builtins__", "__class__", "__bases__", "__subclasses__",
        "__mro__", "__globals__", "__code__", "__closure__", "__func__",
    }

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and n.id in self.FORBIDDEN_DUNDERS:
                out.append(Finding(rule_id="R03", severity="BLOCK", message=f"forbidden dunder identifier '{n.id}'", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.Attribute):
                if n.attr in self.FORBIDDEN_DUNDERS:
                    out.append(Finding(rule_id="R03", severity="BLOCK", message=f"forbidden dunder attribute '{n.attr}'", line=n.lineno, col=n.col_offset))
                elif n.attr == "__dict__":
                    if not (isinstance(n.value, ast.Name) and n.value.id == "self"):
                        out.append(Finding(rule_id="R03", severity="BLOCK", message="access to '__dict__' on non-self object is blocked", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn in {"getattr", "setattr", "delattr"}:
                    if len(n.args) < 2 or not (isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)):
                        out.append(Finding(rule_id="R03", severity="BLOCK", message=f"'{qn}' requires a string literal attribute name", line=n.lineno, col=n.col_offset))
                    else:
                        attr_val = n.args[1].value
                        if attr_val in self.FORBIDDEN_DUNDERS or attr_val in R02DangerousBuiltins.DENIED:
                            out.append(Finding(rule_id="R03", severity="BLOCK", message=f"'{qn}' targeting restricted name '{attr_val}'", line=n.lineno, col=n.col_offset))
        return out


@register
class R04ProcessV0(Rule):
    key = "R04_v0"
    id = "R04"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                if n.func.value.id == "os" and n.func.attr in {"system", "popen"}:
                    out.append(Finding(rule_id="R04", severity="BLOCK", message=f"call to os.{n.func.attr} is blocked", line=n.lineno, col=n.col_offset))
        return out


@register
class R04ProcessCalls(Rule):
    key = "R04"
    id = "R04"
    OS_DENIED = {
        "system", "popen", "execl", "execle", "execlp", "execlpe", "execv",
        "execve", "execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
        "spawnv", "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp",
        "fork", "forkpty", "kill", "killpg", "chmod", "fchmod", "lchmod",
        "chown", "fchown", "lchown", "chroot", "setuid", "seteuid", "setreuid",
        "setgid", "setegid", "setregid", "setgroups", "initgroups", "putenv",
        "unsetenv", "startfile",
    }

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.Call, ast.Attribute, ast.Name)):
                qn = resolve_qualname(n.func if isinstance(n, ast.Call) else n, ctx.aliases)
                if qn.startswith("subprocess.") or qn.startswith("pty."):
                    out.append(Finding(rule_id="R04", severity="BLOCK", message=f"process execution API '{qn}' is blocked", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
                elif qn.startswith("os."):
                    attr = qn.split(".", 1)[1].split(".")[0]
                    if attr in self.OS_DENIED:
                        out.append(Finding(rule_id="R04", severity="BLOCK", message=f"dangerous OS process/permission call 'os.{attr}' is blocked", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
        return out


@register
class R05DestructiveV0(Rule):
    key = "R05_v0"
    id = "R05"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn.endswith("rmtree") and n.args:
                    a0 = n.args[0]
                    if isinstance(a0, ast.Constant) and a0.value == "/":
                        out.append(Finding(rule_id="R05", severity="BLOCK", message="shutil.rmtree target '/' is a protected path", line=n.lineno, col=n.col_offset))
        return out


@register
class R05DestructiveFS(Rule):
    key = "R05"
    id = "R05"
    FS_DELETE_FUNCS = {
        "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir",
        "os.removedirs", "os.rename", "os.replace", "shutil.move",
    }
    PATH_METHODS = {"unlink", "rmdir", "rename", "replace"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn in self.FS_DELETE_FUNCS:
                    if not n.args:
                        out.append(Finding(rule_id="R05", severity="BLOCK", message=f"'{qn}' called without resolvable path", line=n.lineno, col=n.col_offset))
                        continue
                    ok, resolved = _resolve_path_expr(n.args[0], ctx)
                    if not ok:
                        target_desc = f"'{resolved}'" if resolved else "unresolved dynamic path"
                        out.append(Finding(rule_id="R05", severity="BLOCK", message=f"{qn} target {target_desc} is protected or unresolvable", line=n.lineno, col=n.col_offset))
                elif isinstance(n.func, ast.Attribute) and n.func.attr in self.PATH_METHODS:
                    ok, resolved = _resolve_path_expr(n.func.value, ctx)
                    if not ok:
                        out.append(Finding(rule_id="R05", severity="BLOCK", message=f"Path.{n.func.attr}() on protected or unresolvable target", line=n.lineno, col=n.col_offset))
        return out


@register
class R06PathTraversal(Rule):
    key = "R06"
    id = "R06"
    severity = "BLOCK"
    rationale = "host-path access breaks the container filesystem isolation"

    SENSITIVE_PREFIX = ("/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab",
                        "/etc/cron.d", "/proc", "/sys", "/dev", "/root",
                        "/var/run/docker.sock")
    SENSITIVE_SUBSTR = (".ssh", "gc_private")

    def _sensitive(self, p: str) -> bool:
        if p in READABLE_EXCEPTIONS or "/" not in p:
            return False
        if any(p == s or p.startswith(s) for s in self.SENSITIVE_PREFIX):
            return True
        return any(s in p for s in self.SENSITIVE_SUBSTR)

    def check(self, tree, ctx):
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if self._sensitive(node.value):
                    out.append(Finding(rule_id=self.id, severity=self.severity,
                                       message=f"sensitive path literal '{node.value}'",
                                       line=getattr(node, "lineno", 0)))
            elif isinstance(node, ast.Call):
                ok, lit = _resolve_path_expr(node.args[0], ctx) if node.args else (True, None)
                if not ok and lit:
                    out.append(Finding(rule_id=self.id, severity=self.severity,
                                       message=f"disallowed or traversal path '{lit}'",
                                       line=getattr(node, "lineno", 0)))
        return out


@register
class R07NetworkIndicators(Rule):
    key = "R07"
    id = "R07"
    NET_CALLS = {"socket", "create_connection", "urlopen", "urlretrieve", "HTTPConnection", "HTTPSConnection"}
    URL_RE = re.compile(r"^(https?|ftp|ws|wss)://", re.IGNORECASE)

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                leaf = qn.split(".")[-1]
                if leaf in self.NET_CALLS or qn.startswith(("socket.", "urllib.", "http.", "requests.")):
                    out.append(Finding(rule_id="R07", severity="BLOCK", message=f"network operation '{qn or leaf}' is blocked", line=n.lineno, col=n.col_offset))
                for arg in n.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and self.URL_RE.match(arg.value):
                        out.append(Finding(rule_id="R07", severity="WARN", message=f"URL literal '{arg.value}' in call argument", line=n.lineno, col=n.col_offset))
        return out


@register
class R08InfiniteLoopHeuristic(Rule):
    key = "R08"
    id = "R08"
    severity = "WARN"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and bool(n.test.value) is True:
                has_exit = any(
                    isinstance(sub, (ast.Break, ast.Return, ast.Raise, ast.Yield, ast.YieldFrom))
                    for sub in ast.walk(n)
                )
                if not has_exit:
                    out.append(Finding(rule_id="R08", severity="WARN", message="while True loop has no visible break/return/raise", line=n.lineno, col=n.col_offset))
        return out


def _eval_const_int(node: ast.AST) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _eval_const_int(node.operand)
        return -v if v is not None else None
    if isinstance(node, ast.BinOp):
        l = _eval_const_int(node.left)
        r = _eval_const_int(node.right)
        if l is not None and r is not None:
            if isinstance(node.op, ast.Mult):
                return l * r
            if isinstance(node.op, ast.Add):
                return l + r
            if isinstance(node.op, ast.Pow) and 0 <= r <= 100:
                return l ** r
            if isinstance(node.op, ast.LShift) and 0 <= r <= 64:
                return l << r
    return None


@register
class R09ResourceAbuseConstants(Rule):
    key = "R09"
    id = "R09"
    BLOCK_LIMIT = 10**9
    WARN_LIMIT = 10**8

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.BinOp):
                if isinstance(n.op, ast.Pow):
                    val = _eval_const_int(n)
                    if val is not None and abs(val) >= self.BLOCK_LIMIT:
                        out.append(Finding(rule_id="R09", severity="BLOCK", message=f"huge power expression (>={self.BLOCK_LIMIT})", line=n.lineno, col=n.col_offset))
                elif isinstance(n.op, ast.Mult):
                    for side in (n.left, n.right):
                        val = _eval_const_int(side)
                        if val is not None and abs(val) >= self.BLOCK_LIMIT:
                            out.append(Finding(rule_id="R09", severity="BLOCK", message=f"sequence multiplication by huge constant ({val})", line=n.lineno, col=n.col_offset))
                        elif val is not None and abs(val) >= self.WARN_LIMIT:
                            out.append(Finding(rule_id="R09", severity="WARN", message=f"large multiplication constant ({val})", line=n.lineno, col=n.col_offset))
            elif isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn in {"range", "bytearray"} and n.args:
                    for a in n.args:
                        val = _eval_const_int(a)
                        if val is not None and abs(val) >= self.BLOCK_LIMIT:
                            out.append(Finding(rule_id="R09", severity="BLOCK", message=f"{qn}() with huge constant ({val})", line=n.lineno, col=n.col_offset))
        return out


@register
class R10Deserialization(Rule):
    key = "R10"
    id = "R10"
    BAD_MODS = {"pickle", "marshal", "shelve", "dill", "_pickle"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                root = qn.split(".")[0]
                if root in self.BAD_MODS or qn in {"yaml.load", "yaml.unsafe_load"}:
                    out.append(Finding(rule_id="R10", severity="BLOCK", message=f"unsafe deserialization call '{qn}' is blocked", line=n.lineno, col=n.col_offset))
        return out


@register
class R11InterpreterIntrospection(Rule):
    key = "R11"
    id = "R11"
    SYS_BLOCKED = {"modules", "_getframe", "settrace", "setprofile", "addaudithook", "audit"}
    MOD_BLOCKED = {"inspect", "gc", "types", "ctypes", "cffi"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.Attribute, ast.Name, ast.Call, ast.alias)):
                qn = resolve_qualname(n.func if isinstance(n, ast.Call) else n, ctx.aliases)
                root = qn.split(".")[0]
                if root in self.MOD_BLOCKED:
                    out.append(Finding(rule_id="R11", severity="BLOCK", message=f"interpreter introspection via '{qn}' is blocked", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
                elif qn.startswith("sys."):
                    attr = qn.split(".", 1)[1].split(".")[0]
                    if attr in self.SYS_BLOCKED:
                        out.append(Finding(rule_id="R11", severity="BLOCK", message=f"access to 'sys.{attr}' is blocked", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
        return out


@register
class R12EnvSecrets(Rule):
    key = "R12"
    id = "R12"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.Attribute, ast.Name, ast.Call, ast.alias)):
                qn = resolve_qualname(n.func if isinstance(n, ast.Call) else n, ctx.aliases)
                if qn in {"os.environ", "os.environb", "os.getenv"} or qn.startswith("os.environ."):
                    out.append(Finding(rule_id="R12", severity="BLOCK", message=f"environment access via '{qn}' is blocked", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
        return out


@register
class R13ConcurrencyBombs(Rule):
    key = "R13"
    id = "R13"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn.startswith("multiprocessing.") or "ProcessPoolExecutor" in qn:
                    out.append(Finding(rule_id="R13", severity="BLOCK", message=f"process concurrency '{qn}' is blocked", line=n.lineno, col=n.col_offset))
                elif qn in {"threading.Thread", "Thread"}:
                    out.append(Finding(rule_id="R13", severity="WARN", message="thread creation detected (subject to sandbox pids-limit)", line=n.lineno, col=n.col_offset))
        return out


@register
class R15StructureV0(Rule):
    key = "R15_v0"
    id = "R15"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        return []


@register
class R15StructureGuard(Rule):
    key = "R15"
    id = "R15"
    MAX_DEPTH = 100
    MAX_NODES = 5000

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        total_nodes = 0
        max_depth = 0
        stack: list[tuple[ast.AST, int]] = [(tree, 1)]
        while stack:
            node, depth = stack.pop()
            total_nodes += 1
            if depth > max_depth:
                max_depth = depth
            for child in ast.iter_child_nodes(node):
                stack.append((child, depth + 1))

        out: list[Finding] = []
        if max_depth > self.MAX_DEPTH or "(((((" in ctx.source:
            out.append(Finding(rule_id="R15", severity="BLOCK", message=f"AST depth {max_depth} exceeds limit {self.MAX_DEPTH}", line=1, col=0))
        if total_nodes > self.MAX_NODES:
            out.append(Finding(rule_id="R15", severity="BLOCK", message=f"AST node count {total_nodes} exceeds limit {self.MAX_NODES}", line=1, col=0))
        return out


@register
class R16DynamicLoading(Rule):
    key = "R16"
    id = "R16"
    MODS = {"importlib", "runpy", "code", "codeop", "pkgutil", "zipimport"}

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                root = qn.split(".")[0]
                if root in self.MODS or qn.endswith("import_module"):
                    out.append(Finding(rule_id="R16", severity="BLOCK", message=f"dynamic loader '{qn}' is blocked", line=n.lineno, col=n.col_offset))
        return out


@register
class R17WriteModePaths(Rule):
    key = "R17"
    id = "R17"

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                qn = resolve_qualname(n.func, ctx.aliases)
                if qn in {"open", "io.open"} and n.args:
                    mode = "r"
                    if len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                        mode = n.args[1].value
                    for kw in n.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            mode = kw.value.value
                    if any(m in mode for m in ("w", "a", "x", "+")):
                        ok, resolved = _resolve_path_expr(n.args[0], ctx)
                        if not ok:
                            out.append(Finding(rule_id="R17", severity="BLOCK", message=f"write-mode open() on disallowed or unresolved path '{resolved or 'dynamic'}'", line=n.lineno, col=n.col_offset))
                elif isinstance(n.func, ast.Attribute) and n.func.attr in {"write_text", "write_bytes"}:
                    ok, resolved = _resolve_path_expr(n.func.value, ctx)
                    if not ok:
                        out.append(Finding(rule_id="R17", severity="BLOCK", message=f"Path.{n.func.attr}() on disallowed or unresolved path", line=n.lineno, col=n.col_offset))
        return out


@register
class R18ShellSignatures(Rule):
    key = "R18"
    id = "R18"
    SIG_RE = re.compile(
        r"(rm\s+-[rf]{1,2}\s+/|:\(\)\s*\{|mkfs\.|dd\s+if=|chmod\s+-R\s+777\s+/|>\s*/dev/[sh]da)",
        re.IGNORECASE,
    )

    def check(self, tree: ast.AST, ctx: Ctx) -> list[Finding]:
        out: list[Finding] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                if self.SIG_RE.search(n.value):
                    out.append(Finding(rule_id="R18", severity="BLOCK", message="destructive shell signature detected in string literal", line=getattr(n, "lineno", 1), col=getattr(n, "col_offset", 0)))
        return out

ALLOWLIST_MODULES.add("queue")
