from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from vision.contracts import Event, EventType

GRAPH_ORDER = ["plan", "code", "policy_gate", "execute", "reflect", "finalize"]


class RichSink:
    def __init__(self) -> None:
        self.console = Console()
        self.live: Live | None = None
        self.run_id = ""
        self.task = ""
        self.iteration = 0
        self.active_node = "START"
        self.visited_nodes: set[str] = set()
        self.token_buf = ""
        self.policy_data: dict | None = None
        self.sandbox_data: dict | None = None
        self.blocks = 0
        self.tokens = 0
        self.status = "running"

    def start(self) -> None:
        self.live = Live(self.render(), console=self.console, refresh_per_second=8)
        self.live.start()

    def stop(self) -> None:
        if self.live:
            self.live.stop()
            self.live = None

    def __call__(self, ev: Event) -> None:
        p = ev.payload
        self.run_id = ev.run_id
        if ev.type == EventType.RUN_START:
            self.task = p.get("task", "")
        elif ev.type == EventType.ITER_START:
            self.iteration = p.get("iteration", self.iteration)
            self.token_buf = ""
        elif ev.type == EventType.NODE_START:
            self.active_node = p.get("node", "")
            self.visited_nodes.add(self.active_node)
        elif ev.type == EventType.LLM_TOKEN:
            self.token_buf += p.get("token", "")
            self.tokens += 1
        elif ev.type == EventType.POLICY_RESULT:
            self.policy_data = p
            if p.get("decision") == "BLOCK":
                self.blocks += 1
        elif ev.type == EventType.SANDBOX_RESULT:
            self.sandbox_data = p
        elif ev.type == EventType.RUN_END:
            self.status = p.get("status", "done")

        if self.live:
            self.live.update(self.render())

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="agent", ratio=3),
            Layout(name="right", ratio=2),
        )
        layout["right"].split_column(
            Layout(name="policy"),
            Layout(name="sandbox"),
        )

        strip_parts = []
        for n in GRAPH_ORDER:
            if n == self.active_node:
                strip_parts.append(f"[bold black on cyan] {n} [/bold black on cyan]")
            elif n in self.visited_nodes:
                strip_parts.append(f"[dim cyan]{n}[/dim cyan]")
            else:
                strip_parts.append(f"[dim]{n}[/dim]")
        strip = " → ".join(strip_parts)
        header_text = f"[bold]Run:[/bold] {self.run_id} | [bold]Iter:[/bold] {self.iteration} | [bold]Task:[/bold] {self.task[:60]}\n[bold]Graph:[/bold] {strip}"
        layout["header"].update(Panel(header_text, title="VISION LangGraph State"))

        code_view = Syntax(self.token_buf[-1500:] or "# waiting for LLM tokens...", "python", word_wrap=True)
        layout["agent"].update(Panel(code_view, title="Agent (Streamed Generation)", border_style="cyan"))

        if self.policy_data:
            dec = self.policy_data.get("decision")
            style = "green" if dec == "ALLOW" else "red"
            pol_txt = (
                f"[bold {style}]{dec}ED[/bold {style}] (policy {self.policy_data.get('policy_version')})\n"
                f"Rule: {self.policy_data.get('rule_id') or 'None'} (line {self.policy_data.get('line')})\n"
                f"Reason: {self.policy_data.get('reason') or 'Passed all checks'}\n"
                f"Latency: {self.policy_data.get('duration_ms')} ms"
            )
        else:
            style = "white"
            pol_txt = "Waiting for policy_gate..."
        layout["policy"].update(Panel(pol_txt, title="Layer 1: AST Policy Gate", border_style=style))

        if self.sandbox_data:
            ec = self.sandbox_data.get("exit_code")
            sb_style = "green" if ec == 0 and not self.sandbox_data.get("timed_out") else "red"
            sb_txt = (
                f"Exit Code: {ec} | Duration: {self.sandbox_data.get('duration_ms')} ms\n"
                f"Flags: timeout={self.sandbox_data.get('timed_out')} OOM={self.sandbox_data.get('oom_killed')} "
                f"truncated={self.sandbox_data.get('truncated')}\n"
                f"Stdout: {(self.sandbox_data.get('stdout') or '').strip()[-200:]}\n"
                f"Stderr: {(self.sandbox_data.get('stderr') or '').strip()[-200:]}"
            )
        else:
            sb_style = "white"
            sb_txt = "Waiting for execute..."
        layout["sandbox"].update(Panel(sb_txt, title="Layer 2: Docker Sandbox", border_style=sb_style))

        footer_txt = (
            f"Status: [bold]{self.status.upper()}[/bold] | Iterations: {self.iteration} | "
            f"Policy Blocks: {self.blocks} | Streamed Chunks: {self.tokens}"
        )
        layout["footer"].update(Panel(footer_txt))
        return layout
