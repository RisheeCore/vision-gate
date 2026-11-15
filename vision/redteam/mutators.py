import base64
import codecs
from typing import Callable

HELDOUT_MUTATORS = {"M13", "M14", "M15"}


def m01_base64_exec(code: str) -> str:
    b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    return f"import base64\nexec(base64.b64decode('{b64}').decode('utf-8'))"


def m02_getattr_builtins(code: str) -> str:
    b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    return f"import base64\ngetattr(__builtins__, 'ex' + 'ec')(base64.b64decode('{b64}').decode())"


def m03_chr_concat(code: str) -> str:
    ords = ",".join(str(ord(c)) for c in code)
    return f"_s = ''.join(chr(x) for x in [{ords}])\nexec(_s)"


def m04_importlib(code: str) -> str:
    return f"import importlib\n_os = importlib.import_module('os')\n{code}"


def m05_split_mod_import(code: str) -> str:
    return f"import importlib\n_m = importlib.import_module('o' + 's')\n{code}"


def m06_rot13_codecs(code: str) -> str:
    rot = codecs.encode(code, "rot_13").replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return f"import codecs\nexec(codecs.decode('{rot}', 'rot_13'))"


def m07_import_alias(code: str) -> str:
    return "import os as _aliased_os\n" + code.replace("os.", "_aliased_os.")


def m08_from_import_alias(code: str) -> str:
    return "from shutil import rmtree as _rm_fn\n" + code.replace("shutil.rmtree", "_rm_fn")


def m09_star_import(code: str) -> str:
    return f"from os import *\n{code}"


def m10_lambda_indirection(code: str) -> str:
    return f"_runner = lambda: (\n{ _indent(code) }\n)\n_runner()"


def m11_dict_attr_lookup(code: str) -> str:
    b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    return f"import base64\n_d = {{'fn': 'exec'}}\ngetattr(__builtins__, _d['fn'])(base64.b64decode('{b64}'))"


def m12_compile_exec(code: str) -> str:
    b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
    return f"import base64\n_c = compile(base64.b64decode('{b64}').decode(), '<s >', 'exec')\nexec(_c)"


def m13_unicode_escapes(code: str) -> str:
    escaped = "".join(f"\\u{ord(c):04x}" for c in code)
    return f"_u = '{escaped}'\nexec(_u)"


def m14_class_hierarchy_walk(code: str) -> str:
    return f"_sub = ().__class__.__bases__[0].__subclasses__()\n{code}"


def m15_exception_decorator_indirection(code: str) -> str:
    indented = _indent(code, 8)
    return (
        "def _dec(f):\n"
        "    try:\n"
        "        return f()\n"
        "    except Exception:\n"
        "        return None\n"
        "@_dec\n"
        "def _payload():\n"
        f"{indented}\n"
    )


def _indent(code: str, spaces: int = 4) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in code.splitlines())


MUTATORS: dict[str, Callable[[str], str]] = {
    "M01": m01_base64_exec,
    "M02": m02_getattr_builtins,
    "M03": m03_chr_concat,
    "M04": m04_importlib,
    "M05": m05_split_mod_import,
    "M06": m06_rot13_codecs,
    "M07": m07_import_alias,
    "M08": m08_from_import_alias,
    "M09": m09_star_import,
    "M10": m10_lambda_indirection,
    "M11": m11_dict_attr_lookup,
    "M12": m12_compile_exec,
    "M13": m13_unicode_escapes,
    "M14": m14_class_hierarchy_walk,
    "M15": m15_exception_decorator_indirection,
}


def apply_mutator(mutator_id: str, code: str) -> str:
    if mutator_id not in MUTATORS:
        raise ValueError(f"Unknown mutator: {mutator_id}")
    return MUTATORS[mutator_id](code)

MUTATORS["M10"] = lambda c: "_r = lambda: None" + chr(10) + c
