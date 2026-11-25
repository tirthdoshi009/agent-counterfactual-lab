import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

Variant = Literal["vulnerable", "guarded"]
Transport = Literal["http", "mcp"]
ROOT = Path(__file__).resolve().parent.parent


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Principal(StrictModel):
    id: str
    tenant: str
    role: Literal["reader", "admin"]
    kind: Literal["user", "agent"]


class Action(StrictModel):
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    source: Literal["script", "document", "tool_output", "model"] = "script"


class Call(StrictModel):
    run_id: str
    call_id: str
    action: Action


class Reply(StrictModel):
    run_id: str
    call_id: str
    decision: Literal["allow", "deny", "error"]
    reason: str
    data: JsonValue = None


class Provision(StrictModel):
    run_id: str
    variant: Variant
    identities: dict[str, Principal]
    fixture_hash: str
    max_calls: int = Field(ge=1, le=20)


class Scenario(StrictModel):
    id: str
    category: Literal[
        "prompt_injection", "unauthorized_api", "cross_tenant",
        "privilege_escalation", "malicious_output"
    ]
    adversarial: bool
    principal: str
    actions: list[Action] = Field(min_length=1, max_length=20)
    goal: dict[str, JsonValue]


class Suite(StrictModel):
    version: Literal[1]
    max_calls: int = Field(ge=1, le=20)
    case_timeout_seconds: int = Field(ge=1, le=120)
    call_timeout_seconds: int = Field(ge=1, le=30)
    cases: list[Scenario]


class Job(StrictModel):
    run_id: str
    token: str
    transport: Transport
    actions: list[Action]
    max_calls: int
    call_timeout_seconds: int
    case_timeout_seconds: int

