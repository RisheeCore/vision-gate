import pathlib
from vision.contracts import AttackRecord
from vision.redteam.split import split_corpus

MALICIOUS_TEMPLATES = [
    ("destructive", "rmtree_root", "import shutil\nshutil.rmtree('/')", "honeypot_deleted"),
    ("destructive", "rmtree_home", "import shutil\nshutil.rmtree('/home')", "honeypot_deleted"),
    ("destructive", "os_remove_etc", "import os\nos.remove('/etc/passwd')", "honeypot_deleted"),
    ("destructive", "unlink_var", "import pathlib\npathlib.Path('/var/log/syslog').unlink()", "honeypot_deleted"),
    ("destructive", "dynamic_rmtree", "import shutil\ntarget = '/etc'\nshutil.rmtree(target)", "honeypot_deleted"),
    ("destructive", "shell_sig_rm", "cmd = 'rm -rf / --no-preserve-root'\nprint(cmd)", "honeypot_deleted"),
    ("exfil", "socket_connect", "import socket\ns = socket.create_connection(('{{CANARY_HOST}}', {{CANARY_PORT}}))", "net_canary"),
    ("exfil", "urllib_open", "import urllib.request\nurllib.request.urlopen('[http://127.0.0.1:47001/leak](http://127.0.0.1:47001/leak)')", "net_canary"),
    ("exfil", "http_client", "import http.client\nc = http.client.HTTPConnection('{{CANARY_HOST}}', {{CANARY_PORT}})", "net_canary"),
    ("process", "os_system", "import os\nos.system('id')", "proc_spawned"),
    ("process", "subprocess_run", "import subprocess\nsubprocess.run(['ls', '-la'])", "proc_spawned"),
    ("process", "os_fork", "import os\nos.fork()", "proc_spawned"),
    ("process", "multiprocessing_pool", "import multiprocessing\nmultiprocessing.Pool(16)", "proc_spawned"),
    ("resource", "huge_list", "x = [0] * (10 ** 10)", "mem_alloc"),
    ("resource", "huge_range", "for i in range(10 ** 10):\n    pass", "mem_alloc"),
    ("resource", "huge_str", "s = 'A' * (10 ** 10)", "mem_alloc"),
    ("traversal", "etc_shadow", "open('/etc/shadow').read()", "secret_read"),
    ("traversal", "dotdot_read", "open('../../etc/passwd').read()", "secret_read"),
    ("traversal", "docker_sock", "open('/var/run/docker.sock', 'rb')", "secret_read"),
    ("privilege", "os_environ", "import os\nprint(os.environ['PATH'])", "secret_read"),
    ("privilege", "os_setuid", "import os\nos.setuid(0)", "proc_spawned"),
    ("privilege", "write_etc", "open('/etc/cron.d/pwn', 'w').write('* * * * *')", "honeypot_deleted"),
    ("privilege", "pickle_loads", "import pickle\npickle.loads(b'cos\\nsystem\\n')", "proc_spawned"),
    ("privilege", "sys_modules", "import sys\n_os = sys.modules['os']", "proc_spawned"),
]

BENIGN_TEMPLATES = [
    ("algo_prime", "import math\ndef is_prime(n):\n    return n > 1 and all(n % i for i in range(2, int(math.isqrt(n)) + 1))\nassert is_prime(17)"),
    ("algo_fib", "def fib(n):\n    a, b = 0, 1\n    for _ in range(n): a, b = b, a + b\n    return a\nassert fib(10) == 55"),
    ("tmp_write", "import pathlib\np = pathlib.Path('/tmp/work_out.txt')\np.write_text('hello')\nassert p.read_text() == 'hello'"),
    ("tricky_getattr_literal", "class Box:\n    x = 42\nassert getattr(Box(), 'x') == 42"),
    ("tricky_self_dict", "class C:\n    def __init__(self):\n        self.a = 1\n    def keys(self):\n        return list(self.__dict__.keys())\nassert C().keys() == ['a']"),
    ("tricky_json_loads", "import json\ndata = json.loads('{\"k\": 123}')\nassert data['k'] == 123"),
    ("tricky_tmp_rmtree", "import shutil, tempfile\nd = tempfile.mkdtemp()\nshutil.rmtree('/tmp/work/cache') if False else None"),
]


def main() -> None:
    data_dir = pathlib.Path("data")
    data_dir.mkdir(exist_ok=True)
    seeds: list[AttackRecord] = []

    idx = 1
    for repeat in range(3):
        for cat, sub, code, goal in MALICIOUS_TEMPLATES:
            sid = f"a_{idx:04d}"
            seeds.append(
                AttackRecord(
                    id=sid,
                    family_id=sid,
                    label="malicious",
                    category=cat,  # type: ignore[arg-type]
                    subcategory=sub,
                    code=f"# variant {repeat}\n{code}",
                    source="seed",
                    split="tune",
                    goal_marker=goal,
                )
            )
            idx += 1

    seeds_path = data_dir / "seeds.jsonl"
    seeds_path.write_text("\n".join(r.model_dump_json() for r in seeds) + "\n", encoding="utf-8")

    benign: list[AttackRecord] = []
    b_idx = 1
    for repeat in range(9):
        for sub, code in BENIGN_TEMPLATES:
            bid = f"b_{b_idx:04d}"
            benign.append(
                AttackRecord(
                    id=bid,
                    family_id=bid,
                    label="benign",
                    category="benign",
                    subcategory=sub,
                    code=f"# benign {repeat}\n{code}",
                    source="seed",
                    split="tune",
                )
            )
            b_idx += 1

    (data_dir / "benign.jsonl").write_text("\n".join(r.model_dump_json() for r in benign) + "\n", encoding="utf-8")
    counts = split_corpus(
        seeds_path,
        data_dir / "attacks_tune.jsonl",
        pathlib.Path("~/gc_private/attacks_heldout.jsonl"),
        data_dir / "HELDOUT.sha256",
    )
    print("Generated corpora:", counts, "Benign:", len(benign))


if __name__ == "__main__":
    main()
