import pathlib
import socket
import subprocess
import time
import pytest
from vision.sandbox.canary import CanaryMonitor
from vision.sandbox.runner import run

pytestmark = pytest.mark.docker


def test_s01_basic_stdout():
    res = run("print(123)")
    assert res.exit_code == 0
    assert res.stdout.strip() == "123"


def test_s02_timeout():
    res = run("while True: pass", timeout_s=2.0)
    assert res.timed_out is True
    assert res.duration_ms <= 5500


def test_s03_fork_bomb_contained():
    code = "import os" + chr(10) + "while True:" + chr(10) + "    os.fork()"
    res = run(code, timeout_s=3.0)
    assert res.exit_code != 0 or res.timed_out


def test_s04_oom_killed():
    code = "a = []" + chr(10) + "while True:" + chr(10) + "    a.append(bytearray(10 * 1024 * 1024))" + chr(10) + "    a[-1][0] = 1"
    res = run(code, timeout_s=5.0)
    assert res.oom_killed is True or res.exit_code != 0


def test_s05_no_network():
    code = "import socket" + chr(10) + "socket.create_connection((chr(49)+chr(46)+chr(49)+chr(46)+chr(49)+chr(46)+chr(49), 80), timeout=1)"
    res = run(code, timeout_s=5.0)
    assert res.exit_code != 0


def test_s06_read_only_root():
    res = run("open(chr(47)+chr(101)+chr(116)+chr(99)+chr(47)+chr(120), chr(119)).write(chr(97))")
    assert res.exit_code != 0


def test_s07_tmpfs_size_cap():
    res_ok = run("open(chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(102), chr(119)+chr(98)).write(bytes(1024 * 1024))")
    assert res_ok.exit_code == 0
    res_fail = run("open(chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(98), chr(119)+chr(98)).write(bytes(32 * 1024 * 1024))")
    assert res_fail.exit_code != 0


def test_s08_tmp_noexec():
    code = (
        "import os, subprocess" + chr(10)
        + "p = chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(115)" + chr(10)
        + "open(p, chr(119)).write(chr(35)+chr(33)+chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(104)+chr(10))" + chr(10)
        + "os.chmod(p, 0o755)" + chr(10)
        + "subprocess.run([p], check=True)"
    )
    res = run(code)
    assert res.exit_code != 0


def test_s09_unprivileged_uid():
    res = run("import os; print(os.getuid())")
    assert res.stdout.strip() == "65534"


def test_s10_zero_capabilities():
    code = (
        "for ln in open(chr(47)+chr(112)+chr(114)+chr(111)+chr(99)+chr(47)+chr(115)+chr(101)+chr(108)+chr(102)+chr(47)+chr(115)+chr(116)+chr(97)+chr(116)+chr(117)+chr(115)):" + chr(10)
        + "    if ln.startswith(chr(67)+chr(97)+chr(112)+chr(69)+chr(102)+chr(102)+chr(58)):" + chr(10)
        + "        print(ln.split()[1])"
    )
    res = run(code)
    assert int(res.stdout.strip(), 16) == 0


def test_s11_bounded_output_flood():
    res = run("while True: print(1234567890 * 100)", timeout_s=5.0)
    assert res.truncated is True


def test_s12_no_leftover_containers():
    r = subprocess.run(["docker", "ps", "-aq", "--filter", "label=gc=1"], capture_output=True, text=True)
    assert r.stdout.strip() == ""


def test_s13_positive_control_network_canary(tmp_path: pathlib.Path):
    with CanaryMonitor(canary_dir=tmp_path, port=0) as mon:
        with socket.create_connection(("127.0.0.1", mon.port), timeout=1.0) as s:
            s.sendall(b"ping")
        time.sleep(0.05)
        assert mon.check_touched() is True


def test_s14_positive_control_file_canary(tmp_path: pathlib.Path):
    with CanaryMonitor(canary_dir=tmp_path, port=0) as mon:
        assert mon.check_touched() is False
        mon.canary_file.write_text("tampered", encoding="utf-8")
        assert mon.check_touched() is True


def test_s15_strict_profile_canary_silent(tmp_path: pathlib.Path):
    with CanaryMonitor(canary_dir=tmp_path, port=0) as mon:
        code = f"import socket; socket.create_connection(((chr(49)+chr(50)+chr(55)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49)), {mon.port}), timeout=1)"
        res = run(code, canary=mon)
        assert res.canary_touched is False
