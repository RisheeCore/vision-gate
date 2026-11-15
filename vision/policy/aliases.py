import ast
from dataclasses import dataclass, field


@dataclass
class Ctx:
    source: str
    aliases: dict[str, str] = field(default_factory=dict)
    star_imports: list[tuple[str, int]] = field(default_factory=list)
    string_vars: dict[str, str] = field(default_factory=dict)
    safe_root_vars: set[str] = field(default_factory=set)


def resolve_qualname(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, (ast.Name, ast.alias)):
        k = getattr(node, "id", None) or node.asname or node.name; return aliases.get(k, k)
    if isinstance(node, ast.Attribute):
        prefix = resolve_qualname(node.value, aliases)
        if prefix:
            full = f"{prefix}.{node.attr}"
            return aliases.get(full, full)
    return ""


def build_context(tree: ast.AST, source: str) -> Ctx:
    aliases: dict[str, str] = {}
    star_imports: list[tuple[str, int]] = []
    string_vars: dict[str, str] = {}
    safe_root_vars: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    star_imports.append((mod, getattr(node, "lineno", 1)))
                else:
                    local = alias.asname or alias.name
                    aliases[local] = f"{mod}.{alias.name}" if mod else alias.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            val = node.value
            if isinstance(val, (ast.Name, ast.Attribute)):
                qn = resolve_qualname(val, aliases)
                if qn:
                    aliases[target] = qn
            elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                string_vars[target] = val.value
            elif isinstance(val, ast.Call):
                qn = resolve_qualname(val.func, aliases)
                if qn in {
                    "tempfile.mkdtemp",
                    "tempfile.TemporaryDirectory",
                    "tempfile.NamedTemporaryFile",
                }:
                    safe_root_vars.add(target)
                elif qn in {"pathlib.Path", "Path"} and val.args:
                    arg0 = val.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        if arg0.value.startswith(("/tmp", "/work")) or (
                            not arg0.value.startswith("/") and ".." not in arg0.value
                        ):
                            safe_root_vars.add(target)

    return Ctx(
        source=source,
        aliases=aliases,
        star_imports=star_imports,
        string_vars=string_vars,
        safe_root_vars=safe_root_vars,
    )
