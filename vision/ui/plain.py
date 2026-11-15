from rich.console import Console
from vision.contracts import Event, EventType


class PlainSink:
    def __init__(self) -> None:
        self.console = Console()

    def __call__(self, ev: Event) -> None:
        p = ev.payload
        if ev.type == EventType.RUN_START:
            self.console.print(f"[bold cyan]▶ RUN START[/bold cyan] id={ev.run_id} task={p.get('task')}")
        elif ev.type == EventType.NODE_START:
            self.console.print(f"[cyan]  • node:[/cyan] [bold]{p.get('node')}[/bold] (iter {p.get('iteration')})")
        elif ev.type == EventType.POLICY_RESULT:
            dec = p.get("decision")
            color = "green" if dec == "ALLOW" else "bold red"
            self.console.print(f"  [{color}]POLICY {dec}[/{color}] rule={p.get('rule_id')} reason={p.get('reason')}")
        elif ev.type == EventType.SANDBOX_RESULT:
            code = p.get("exit_code")
            color = "green" if code == 0 and not p.get("timed_out") else "red"
            self.console.print(
                f"  [{color}]SANDBOX exit={code}[/{color}] time={p.get('duration_ms')}ms "
                f"timeout={p.get('timed_out')} oom={p.get('oom_killed')}"
            )
        elif ev.type == EventType.RUN_END:
            st = p.get("status")
            color = "bold green" if st == "success" else "bold red"
            self.console.print(f"[{color}]■ RUN END: {st.upper()}[/{color}] (iterations={p.get('iterations')})")
