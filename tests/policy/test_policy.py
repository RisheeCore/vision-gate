import pytest
from vision.policy.engine import check


@pytest.mark.parametrize(
    "rule_id,bad_samples,good_samples",
    [
        ("R00", ["def f(:", "if True", "x = [1, 2"], ["x = 1", "def f(): return 2", "import math"]),
        ("R01", ["import subprocess", "import socket as s", "from ctypes import cdll"], ["import math", "import json", "from collections import deque"]),
        ("R02", ["eval('1')", "f = exec", "globals()['x']"], ["def evaluate(x): return x", "x = 10", "print('ok')"]),
        ("R03", ["getattr(obj, 'a' + 'b')", "x.__class__.__bases__", "other.__dict__"], ["getattr(obj, 'name')", "self.__dict__['a'] = 1", "hasattr(obj, 'x')"]),
        ("R04", ["import os\nos.system('ls')", "import os\nos.fork()", "import os\nos.chmod('/tmp/a', 0o777)"], ["import os\nos.getcwd()", "import os\nos.path.join('/tmp', 'a')", "import os\nprint(os.name)"]),
        ("R05", ["import shutil\nshutil.rmtree('/')", "import os\nos.remove('/etc/hosts')", "import shutil\nshutil.rmtree(dyn_var)"], ["import shutil\nshutil.rmtree('/tmp/work/dir')", "import os\nos.remove('/tmp/test.txt')", "import os\nos.remove('local_rel.txt')"]),
        ("R06", ["open('/etc/shadow')", "open('../../secret.txt')", "open('/var/run/docker.sock')"], ["open('data.txt')", "open('/tmp/input.txt')", "open('/work/notes.txt')"]),
        ("R07", ["import urllib.request\nurllib.request.urlopen('[http://example.com](http://example.com)')", "s.create_connection(('1.1.1.1', 80))", "sock.socket()"], ["x = 'hello'", "import math\nmath.sin(1)", "import json\njson.dumps({})"]),
        ("R09", ["x = [0] * 10**10", "for i in range(10**10): pass", "s = 'a' * (10**9)"], ["x = [0] * 1000", "for i in range(500): pass", "y = 2 ** 16"]),
        ("R10", ["import pickle\npickle.loads(b'')", "import marshal\nmarshal.loads(b'')", "yaml.load(s)"], ["import json\njson.loads('{}')", "import csv", "x = [1, 2, 3]"]),
        ("R11", ["import sys\nsys.modules['os']", "import sys\nsys._getframe()", "import inspect\ninspect.stack()"], ["import sys\nprint(sys.version)", "import sys\nsys.exit(0)", "import math"]),
        ("R12", ["import os\nprint(os.environ)", "import os\nos.getenv('SECRET')", "from os import environ"], ["import os\nos.getcwd()", "x = 'environ'", "print(123)"]),
        ("R13", ["import multiprocessing\nmultiprocessing.Pool(4)", "ProcessPoolExecutor()", "multiprocessing.Process()"], ["import threading\nlk = threading.Lock()", "x = 1", "import queue"]),
        ("R15", ["x = '" + ("a" * 21000) + "'", "(" * 120 + "1" + ")" * 120, "+".join(["1"] * 5100)], ["x = 1 + 2", "def f(a): return a * 2", "for i in range(10): print(i)"]),
        ("R16", ["import importlib\nimportlib.import_module('os')", "import runpy\nrunpy.run_module('x')", "import code\ncode.interact()"], ["import math", "import itertools", "import functools"]),
        ("R17", ["open('/etc/passwd', 'w')", "open(unknown_var, 'a')", "Path('/root/x').write_text('a')"], ["open('/tmp/out.txt', 'w')", "open('relative.txt', 'w')", "open('/etc/hostname', 'r') or True"]),
        ("R18", ["s = 'rm -rf /'", "s = ':(){ :|:& };:'", "s = 'dd if=/dev/zero of=/dev/sda'"], ["s = 'hello world'", "s = 'remove file'", "s = 'normal text'"]),
    ],
)
def test_rule_malicious_and_benign(rule_id: str, bad_samples: list[str], good_samples: list[str]):
    for bad in bad_samples:
        res = check(bad, "v3")
        assert res.decision == "BLOCK", f"Expected {rule_id} to BLOCK: {bad}"
    for good in good_samples:
        res = check(good, "v3")
        assert res.decision == "ALLOW", f"Unexpected FP ({res.rule_id}: {res.reason}) on: {good}"


def test_determinism_and_latency():
    sample = "import math\n" + "\n".join(f"x_{i} = math.sqrt({i})" for i in range(150))
    r1 = check(sample, "v3")
    r2 = check(sample, "v3")
    assert r1.decision == r2.decision == "ALLOW"
    assert r1.findings == r2.findings
    assert r1.duration_ms < 20.0


def test_v0_vs_v3_progression():
    alias_bypass = "import os as o\nprint(o.environ)"
    assert check(alias_bypass, "v0").decision == "ALLOW"
    assert check(alias_bypass, "v3").decision == "BLOCK"
