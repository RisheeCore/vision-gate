import functools
import pathlib
import time
from typing import Callable
from vision.contracts import Event, EventType


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        if fn not in self._subscribers:
            self._subscribers.append(fn)

    def unsubscribe(self, fn: Callable[[Event], None]) -> None:
        if fn in self._subscribers:
            self._subscribers.remove(fn)

    def clear(self) -> None:
        self._subscribers.clear()

    def emit(self, run_id: str, event_type: EventType, **payload) -> Event:
        ev = Event(ts=time.time(), run_id=run_id, type=event_type, payload=payload)
        for sub in list(self._subscribers):
            try:
                sub(ev)
            except Exception:
                pass
        return ev


BUS = EventBus()


def emit(run_id: str, event_type: EventType, **payload) -> Event:
    return BUS.emit(run_id, event_type, **payload)


def emit_error(run_id: str, exc: BaseException) -> Event:
    return BUS.emit(run_id, EventType.ERROR, error=type(exc).__name__, message=str(exc))


class JsonlSink:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, event: Event) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")


def traced(node_name: str):
    """Decorator emitting NODE_START and NODE_END around LangGraph node functions."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(state: dict, *args, **kwargs):
            run_id = state.get("run_id", "unknown")
            t0 = time.perf_counter()
            emit(run_id, EventType.NODE_START, node=node_name, iteration=state.get("iteration", 0))
            try:
                out = fn(state, *args, **kwargs)
                dur = (time.perf_counter() - t0) * 1000.0
                emit(run_id, EventType.NODE_END, node=node_name, duration_ms=round(dur, 2))
                return out
            except Exception as e:
                dur = (time.perf_counter() - t0) * 1000.0
                emit(run_id, EventType.NODE_END, node=node_name, duration_ms=round(dur, 2), error=str(e))
                raise
        return wrapper
    return decorator
