import os
import subprocess
import threading
import time
import uuid
from typing import Optional
from vision.contracts import SandboxResult
from vision.sandbox.profiles import PROFILES
from vision.sandbox.canary import CanaryMonitor

MAX_STREAM = 64 * 1024


def _reader(stream, buf: bytearray, flag: dict, kill_fn) -> None:
    while True:
        try:
            chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
        except Exception:
            return
        if not chunk:
            return
        room = MAX_STREAM - len(buf)
        if room > 0:
            buf.extend(chunk[:room])
        if len(chunk) > room:
            flag["truncated"] = True
            kill_fn()
            return


def run(
    code: str,
    timeout_s: float = 10.0,
    profile: str = "strict",
    canary: Optional[CanaryMonitor] = None,
) -> SandboxResult:
    if profile not in PROFILES:
        raise ValueError(f"Unknown sandbox profile: {profile}")

    image = os.environ.get("GC_SANDBOX_IMAGE", "vision-sandbox:latest")
    name = f"gc-{uuid.uuid4().hex[:12]}"
    flags = list(PROFILES[profile])
    if canary is not None and profile == "strict_canary":
        flags = [f.replace("__CANARY_DIR__", str(canary.canary_dir)) for f in flags]

    if canary is not None:
        canary.reset()

    cmd = [
        "docker", "run", "-i",
        "--name", name,
        "--label", "gc=1",
        "--pull=never",
        *flags,
        image,
        "python", "-I", "-B", "-",
    ]

    out = bytearray()
    err = bytearray()
    flag = {"truncated": False}
    t0 = time.perf_counter()

    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def kill_container() -> None:
        subprocess.Popen(
            ["docker", "kill", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            p.kill()
        except Exception:
            pass

    ths = [
        threading.Thread(target=_reader, args=(p.stdout, out, flag, kill_container), daemon=True),
        threading.Thread(target=_reader, args=(p.stderr, err, flag, kill_container), daemon=True),
    ]
    for t in ths:
        t.start()

    try:
        assert p.stdin is not None
        p.stdin.write(code.encode("utf-8", errors="replace"))
        p.stdin.close()
    except (BrokenPipeError, OSError):
        pass

    timed_out = False
    try:
        p.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_container()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()

    for t in ths:
        t.join(timeout=1)

    stdout_str = out.decode("utf-8", errors="replace")
    stderr_str = err.decode("utf-8", errors="replace")

    oom = False
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.OOMKilled}}", name],
            capture_output=True,
            text=True,
            timeout=3,
        )
        oom = (
            r.stdout.strip().lower() == "true"
            or "MemoryError" in stderr_str
            or (p.returncode in (137, -9) and not timed_out and not flag["truncated"])
        )
    except Exception:
        oom = "MemoryError" in stderr_str
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    dur_ms = (time.perf_counter() - t0) * 1000.0
    exit_code = p.returncode if p.returncode is not None else -1
    canary_touched = canary.check_touched() if canary is not None else False

    return SandboxResult(
        stdout=stdout_str,
        stderr=stderr_str,
        exit_code=exit_code,
        timed_out=timed_out,
        oom_killed=oom,
        truncated=flag["truncated"],
        duration_ms=round(dur_ms, 2),
        canary_touched=canary_touched,
    )
