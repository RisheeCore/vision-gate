import operator
from typing import Annotated, Literal, Optional, TypedDict


class AgentState(TypedDict):
    run_id: str
    task: str
    config: dict
    plan: Optional[str]
    code: Optional[str]
    last_code_sha: Optional[str]
    repeats: int
    approved_sha256: Optional[str]
    policy: Optional[dict]
    sandbox: Optional[dict]
    feedback: Optional[str]
    iteration: int
    history: Annotated[list[dict], operator.add]
    status: Literal["running", "success", "failed"]
