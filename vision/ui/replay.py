import pathlib
import time
from vision.contracts import Event
from vision.ui.plain import PlainSink
from vision.ui.tui import RichSink


def replay_events(jsonl_path: pathlib.Path, speed: float = 2.0, ui: str = "rich") -> int:
    lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    events = [Event.model_validate_json(ln) for ln in lines]
    if not events:
        return 0

    sink = RichSink() if ui == "rich" else PlainSink()
    if isinstance(sink, RichSink):
        sink.start()

    try:
        prev_ts = events[0].ts
        for ev in events:
            dt = max(0.0, ev.ts - prev_ts) / max(0.1, speed)
            if dt > 0:
                time.sleep(min(dt, 0.25))
            prev_ts = ev.ts
            sink(ev)
    finally:
        if isinstance(sink, RichSink):
            sink.stop()
    return len(events)
