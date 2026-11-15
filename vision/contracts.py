from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Finding(BaseModel):
    rule_id: str
    severity: Literal["BLOCK", "WARN"]
    message: str
    line: Optional[int] = None
    col: Optional[int] = None


class PolicyResult(BaseModel):
    decision: Decision
    rule_id: Optional[str] = None
    reason: str = ""
    line: Optional[int] = None
    findings: list[Finding] = Field(default_factory=list)
    policy_version: str
    duration_ms: float


class SandboxResult(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    oom_killed: bool = False
    truncated: bool = False
    duration_ms: float
    canary_touched: bool = False


class Outcome(str, Enum):
    AST_BLOCKED = "AST_BLOCKED"
    SANDBOX_CONTAINED = "SANDBOX_CONTAINED"
    ESCAPED = "ESCAPED"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AttackRecord(BaseModel):
    id: str
    family_id: str
    label: Literal["malicious", "benign"]
    category: Literal[
        "destructive",
        "exfil",
        "process",
        "resource",
        "traversal",
        "privilege",
        "obfuscated",
        "benign",
    ]
    subcategory: Optional[str] = None
    code: str
    source: Literal["seed", "mutator", "llm", "human"]
    mutator: Optional[str] = None
    parent_id: Optional[str] = None
    split: Literal["tune", "heldout"]
    goal_marker: Optional[str] = None
    round_created: int = 0
    notes: str = ""


class EventType(str, Enum):
    RUN_START = "run_start"
    ITER_START = "iter_start"
    NODE_START = "node_start"
    NODE_END = "node_end"
    LLM_REQUEST = "llm_request"
    LLM_TOKEN = "llm_token"
    LLM_RESPONSE = "llm_response"
    POLICY_RESULT = "policy_result"
    SANDBOX_START = "sandbox_start"
    SANDBOX_RESULT = "sandbox_result"
    FEEDBACK = "feedback"
    RUN_END = "run_end"
    ERROR = "error"


class Event(BaseModel):
    ts: float
    run_id: str
    type: EventType
    payload: dict
