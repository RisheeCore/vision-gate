"""
Docker flag profiles.
Every flag mitigates a specific host or container threat:
- --network none: prevents exfiltration, C2, SSRF
- --read-only: prevents root filesystem tampering/persistence
- --cap-drop ALL: drops all Linux capabilities (raw sockets, mount, chown, ptrace)
- --security-opt no-new-privileges: blocks setuid privilege escalation
- --pids-limit 64: contains fork bombs
- --memory 256m --memory-swap 256m: hard RAM cap without swap thrashing
- --cpus 0.5: prevents host CPU starvation
- --user 65534:65534: runs as unprivileged nobody:nogroup
- --init: reaps zombie processes
- --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m: caps scratch space, blocks binary execution from /tmp
- --ulimit nofile/fsize/cpu: restricts open FDs, max file size (10 MiB), and CPU time
"""

STRICT_FLAGS: list[str] = [
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "64",
    "--memory", "256m",
    "--memory-swap", "256m",
    "--cpus", "0.5",
    "--user", "65534:65534",
    "--init",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--ulimit", "nofile=64:64",
    "--ulimit", "fsize=10485760:10485760",
    "--ulimit", "cpu=10:10",
    "-e", "PYTHONDONTWRITEBYTECODE=1",
    "-e", "HOME=/tmp",
    "-w", "/tmp",
]

PERMISSIVE_REFERENCE_FLAGS: list[str] = [
    "--network", "bridge",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "64",
    "--memory", "256m",
    "--memory-swap", "256m",
    "--cpus", "0.5",
    "--user", "65534:65534",
    "--init",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--ulimit", "nofile=64:64",
    "--ulimit", "fsize=10485760:10485760",
    "--ulimit", "cpu=10:10",
    "-e", "PYTHONDONTWRITEBYTECODE=1",
    "-e", "HOME=/tmp",
    "-w", "/tmp",
]

STRICT_GVISOR_FLAGS: list[str] = ["--runtime=runsc", *STRICT_FLAGS]

PROFILES: dict[str, list[str]] = {
    "strict": STRICT_FLAGS,
    "permissive_reference": PERMISSIVE_REFERENCE_FLAGS,
    "strict_gvisor": STRICT_GVISOR_FLAGS,
}

# strict + bridge + writable canary mount: the only profile where a canary can
# fire, therefore the only one that can actually measure an escape.
STRICT_CANARY_FLAGS: list[str] = ["-v", "__CANARY_DIR__:/canary:rw"] + [
    "host" if f == "none" else f for f in STRICT_FLAGS
]

PROFILES["strict_canary"] = STRICT_CANARY_FLAGS
