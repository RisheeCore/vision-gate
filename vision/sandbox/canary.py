import hashlib
import os
import pathlib
import socket
import threading
import uuid
from typing import Optional


class CanaryMonitor:
    """Host-side file and network canary detector."""

    def __init__(
        self,
        canary_dir: Optional[pathlib.Path] = None,
        host: str = "0.0.0.0",
        port: int = 47001,
    ) -> None:
        self.canary_dir = canary_dir or pathlib.Path.home() / ".vision" / "canary"
        self.canary_file = self.canary_dir / "secret.txt"
        self.host = host
        self.port = port
        self._net_hits = 0
        self._stop_event = threading.Event()
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._initial_sha: str = ""
        self._initial_mtime: float = 0.0
        self._initial_listing: list[str] = []

    def start(self) -> None:
        self.canary_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.canary_dir, 0o777)
        token = f"CANARY_SECRET_{uuid.uuid4().hex}\n"
        self.canary_file.write_text(token, encoding="utf-8")
        self.canary_file.chmod(0o666)
        self._snapshot_file_state()

        self._net_hits = 0
        self._stop_event.clear()
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self.port = self._server_sock.getsockname()[1]
        self._server_sock.listen(16)
        self._server_sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def _snapshot_file_state(self) -> None:
        if self.canary_file.exists():
            data = self.canary_file.read_bytes()
            self._initial_sha = hashlib.sha256(data).hexdigest()
            self._initial_mtime = self.canary_file.stat().st_mtime
        else:
            self._initial_sha = ""
            self._initial_mtime = 0.0
        self._initial_listing = sorted(os.listdir(self.canary_dir)) if self.canary_dir.exists() else []

    def _listen_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                assert self._server_sock is not None
                conn, _ = self._server_sock.accept()
                self._net_hits += 1
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def check_touched(self) -> bool:
        if self._net_hits > 0:
            return True
        if not self.canary_file.exists():
            return True
        current_sha = hashlib.sha256(self.canary_file.read_bytes()).hexdigest()
        current_mtime = self.canary_file.stat().st_mtime
        current_listing = sorted(os.listdir(self.canary_dir))
        return (
            current_sha != self._initial_sha
            or current_mtime != self._initial_mtime
            or current_listing != self._initial_listing
        )

    def reset(self) -> None:
        self._net_hits = 0
        if not self.canary_file.exists():
            self.canary_file.write_text(f"CANARY_SECRET_{uuid.uuid4().hex}\n", encoding="utf-8")
        self._snapshot_file_state()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=1.5)

    def __enter__(self) -> "CanaryMonitor":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
