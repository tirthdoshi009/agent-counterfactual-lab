"""Narrow trusted inference/tool RPC. The adapter sends hashes, never arbitrary prompts."""

import asyncio
import copy
import hmac
import json
import secrets
import time
from typing import Literal
import uuid

import httpx
from pydantic import Field, ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lab.adapters.tool_calling import (
    Budget, ModelProvider, ModelTurn, ProviderError, TOOLS, ToolCallingAdapter, assistant_message,
    initial_messages, tool_message,
)
from lab.contracts import Action, Call, Principal, Provision, Reply, StrictModel, digest
from lab.control import State, bearer
from lab.counterfactual import CounterfactualWorkspace, Task, evaluate_trial, load_task
from lab.model_broker import OpenAICompatibleBroker

DATA_URL = "http://10.203.44.1:8000"
CONTROL_URL = "http://127.0.0.1:9000"
MAX_BODY = 16384


class Register(StrictModel):
    condition: Literal["clean", "injected", "neutralized", "unrelated_edit"]
    repeat: int = Field(ge=1, le=5)


class InferenceRequest(StrictModel):
    sequence: int = Field(ge=0, le=7)
    request_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_output_tokens: int = Field(ge=1, le=1024)


class ToolRequest(StrictModel):
    model_tool_id: str = Field(min_length=1, max_length=128)
    call: Call


class Usage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class Observation(StrictModel):
    turns: list[dict]
    transcript: list[dict]
    errors: list[str]
    finished: bool
    usage: Usage


class UpstreamConfig(StrictModel):
    endpoint: str
    approved_endpoints: list[str] = Field(min_length=1, max_length=4)
    model: str
    credential_env: str = Field(pattern=r"^LAB_PROVIDER_[A-Z0-9_]{1,60}$")

    def provider(self, credential: str) -> OpenAICompatibleBroker:
        return OpenAICompatibleBroker(
            endpoint=self.endpoint, approved_endpoints=frozenset(self.approved_endpoints),
            model=self.model, credential=credential,
        )


def response(data: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})


class RequestRejected(ValueError):
    def __init__(self, code: str, status: int):
        self.code, self.status = code, status


async def body(request: Request, schema):
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        raise RequestRejected("json_required", 415)
    if request.headers.get("content-encoding", "identity") != "identity":
        raise RequestRejected("encoded_body_forbidden", 415)
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_BODY:
            raise RequestRejected("request_too_large", 413)
        data.extend(chunk)
    try:
        return schema.model_validate_json(data)
    except ValidationError:
        raise RequestRejected("invalid_request_schema", 400) from None


class Session:
    def __init__(self, task: Task, condition: str, repeat: int, budget: Budget,
                 provider: ModelProvider):
        self.task, self.condition, self.repeat = task, condition, repeat
        self.budget, self.provider = budget, provider
        self.id = str(uuid.uuid4())
        self.capability = secrets.token_urlsafe(32)
        self.created = time.monotonic()
        self.lock = asyncio.Lock()
        self.messages = initial_messages(task.task)
        self.pending = []
        self.seen_ids: set[str] = set()
        self.model_calls = 0
        self.rpc_calls = 0
        self.closed = False
        self.finished = False
        self.errors = []
        self.turns, self.transcript = [], []
        self.usage = {"input_tokens": 0, "output_tokens": 0}
        self.fixture = task.fixture(condition)
        self.state = State(self.fixture)
        token = secrets.token_urlsafe(32)
        self.state.reset(Provision(
            run_id=self.id, variant="guarded", identities={
                token: Principal.model_validate(self.fixture["principals"]["aster-agent"]),
            }, fixture_hash=digest(self.fixture), max_calls=budget.max_tool_calls,
        ))
        self.initial = copy.deepcopy(self.state.snapshot())
        self.workspace = CounterfactualWorkspace(self.state, token)

    def active(self):
        if self.closed or self.finished or self.errors:
            raise RequestRejected("trial_not_active", 409)
        if time.monotonic() - self.created > self.budget.trial_timeout_seconds:
            self.errors.append("trial_timeout")
            raise RequestRejected("trial_timeout", 408)

    async def infer(self, request: InferenceRequest) -> ModelTurn:
        self.active()
        canonical = {"messages": self.messages, "tools": TOOLS}
        size = len(json.dumps(canonical, ensure_ascii=True).encode())
        remaining = self.budget.max_reported_tokens - sum(self.usage.values())
        if self.pending or request.sequence != self.model_calls:
            raise RequestRejected("out_of_order_inference", 409)
        if request.request_hash != digest(canonical):
            raise RequestRejected("conversation_hash_mismatch", 409)
        if (
            self.model_calls >= self.budget.max_model_calls or remaining <= 0
            or request.max_output_tokens > min(self.budget.max_output_tokens, remaining)
            or size > self.budget.max_request_bytes
        ):
            self.errors.append("broker_budget_exhausted")
            raise RequestRejected("broker_budget_exhausted", 429)
        self.model_calls += 1
        try:
            async with asyncio.timeout(min(
                self.budget.call_timeout_seconds,
                self.budget.trial_timeout_seconds - (time.monotonic() - self.created),
            )):
                turn = await self.provider.complete(
                    copy.deepcopy(self.messages), copy.deepcopy(TOOLS), request.max_output_tokens,
                )
        except (ProviderError, TimeoutError):
            self.errors.append("broker_upstream_failure")
            raise RequestRejected("broker_upstream_failure", 502) from None
        self.turns.append({
            "request_hash": digest(canonical), "request_bytes": size, "response": turn.model_dump(),
        })
        self.usage["input_tokens"] += turn.input_tokens
        self.usage["output_tokens"] += turn.output_tokens
        if (
            sum(self.usage.values()) > self.budget.max_reported_tokens
            or turn.output_tokens > request.max_output_tokens
        ):
            self.errors.append("broker_usage_exceeded")
            raise RequestRejected("broker_usage_exceeded", 502)
        if turn.finish_reason in {"length", "content_filter"}:
            self.errors.append(f"incomplete_generation:{turn.finish_reason}")
        elif bool(turn.tool_calls) != (turn.finish_reason == "tool_calls"):
            self.errors.append("conflicting_finish_reason")
        elif turn.tool_calls:
            if any(p.id in self.seen_ids for p in turn.tool_calls) or (
                len({p.id for p in turn.tool_calls}) != len(turn.tool_calls)
            ):
                self.errors.append("duplicate_model_tool_id")
            else:
                self.seen_ids.update(p.id for p in turn.tool_calls)
                self.pending = list(turn.tool_calls)
                self.messages.append(assistant_message(turn))
        else:
            self.finished = True
        return turn

    async def tool(self, request: ToolRequest) -> Reply:
        self.active()
        if not self.pending:
            raise RequestRejected("no_pending_tool", 409)
        proposal = self.pending[0]
        expected = Call(
            run_id=self.id, call_id=f"{self.id}:{len(self.transcript)}",
            action=Action(tool=proposal.name, arguments=proposal.arguments, source="model"),
        )
        if request.model_tool_id != proposal.id or request.call != expected:
            raise RequestRejected("tool_proposal_mismatch", 409)
        if len(self.transcript) >= self.budget.max_tool_calls:
            self.errors.append("tool_call_budget_exhausted")
            raise RequestRejected("tool_call_budget_exhausted", 429)
        reply = await self.workspace.invoke(expected)
        self.pending.pop(0)
        self.messages.append(tool_message(proposal.id, reply))
        self.transcript.append({
            "model_tool_id": proposal.id, "call": expected.model_dump(), "reply": reply.model_dump(),
        })
        if reply.decision == "error":
            self.errors.append(f"tool_error:{reply.reason}")
        return reply

    def evidence(self) -> dict:
        row = {
            "trial_id": self.id, "repeat": self.repeat, "condition": self.condition,
            "provider": copy.deepcopy(self.provider.metadata),
            "condition_hash": digest(self.task.documents()[self.condition]),
            "source_hash": digest(self.task.original_document),
            "reset_verified": self.initial == {
                "run_id": self.id, "fixture_hash": digest(self.fixture),
                "workspace": self.fixture, "audit": [], "capture": [],
            }, "initial_snapshot": copy.deepcopy(self.initial),
            "turns": copy.deepcopy(self.turns), "transcript": copy.deepcopy(self.transcript),
            "errors": list(self.errors), "finished": self.finished, "usage": dict(self.usage),
            "snapshot": copy.deepcopy(self.state.snapshot()),
        }
        row["evaluation"] = evaluate_trial(self.task, row, self.fixture)
        return row


class Broker:
    def __init__(self, provider: ModelProvider, control_token: str, budget: Budget):
        if len(control_token) < 32:
            raise ValueError("A separate strong control capability is required")
        self.provider, self.control_token, self.budget = provider, control_token, budget
        self.task = load_task()
        self.sessions: dict[str, Session] = {}
        self.registered: set[tuple[str, int]] = set()

    def apps(self) -> tuple[Starlette, Starlette]:
        async def rpc(request: Request):
            token = bearer(request)
            session = next(
                (s for s in self.sessions.values() if hmac.compare_digest(token, s.capability)), None,
            )
            if session is None:
                return response({"error": "trial_unauthorized"}, 401)
            session.rpc_calls += 1
            if session.rpc_calls > 2 * (
                session.budget.max_model_calls + session.budget.max_tool_calls
            ) + 4:
                session.errors.append("rpc_request_budget_exhausted")
                return response({"error": "rpc_request_budget_exhausted"}, 429)
            if session.lock.locked():
                return response({"error": "trial_busy"}, 409)
            try:
                async with session.lock:
                    if request.url.path == "/infer":
                        result = await session.infer(await body(request, InferenceRequest))
                    else:
                        result = await session.tool(await body(request, ToolRequest))
                    return response(result.model_dump())
            except RequestRejected as exc:
                return response({"error": exc.code}, exc.status)

        async def control(request: Request):
            if not hmac.compare_digest(bearer(request), self.control_token):
                return response({"error": "control_unauthorized"}, 401)
            try:
                if request.url.path == "/status":
                    return response({"ready": True, "provider": self.provider.metadata})
                if request.url.path == "/trials":
                    register = await body(request, Register)
                    key = (register.condition, register.repeat)
                    if (
                        register.repeat > self.budget.trials_per_condition or key in self.registered
                        or len(self.sessions) >= 4 * self.budget.trials_per_condition
                    ):
                        raise RequestRejected("registration_budget_or_duplicate", 409)
                    session = Session(
                        self.task, register.condition, register.repeat, self.budget, self.provider,
                    )
                    self.registered.add(key)
                    self.sessions[session.id] = session
                    return response({
                        "trial_id": session.id, "capability": session.capability,
                        "task": self.task.task, "budget": self.budget.model_dump(),
                        "provider": self.provider.metadata,
                    })
                session = self.sessions.get(request.path_params["trial_id"])
                if session is None:
                    raise RequestRejected("unknown_trial", 404)
                if session.lock.locked():
                    raise RequestRejected("trial_busy", 409)
                if request.method == "POST":
                    session.closed = True
                return response(session.evidence())
            except RequestRejected as exc:
                return response({"error": exc.code}, exc.status)

        return (
            Starlette(routes=[
                Route("/infer", rpc, methods=["POST"]), Route("/tool", rpc, methods=["POST"]),
            ]),
            Starlette(routes=[
                Route("/status", control, methods=["GET"]),
                Route("/trials", control, methods=["POST"]),
                Route("/trials/{trial_id}", control, methods=["GET", "POST"]),
            ]),
        )


class RPCProvider:
    """Untrusted-side proxy. Holds only one trial capability, never an upstream credential."""

    def __init__(self, registration: dict, transport: httpx.AsyncBaseTransport | None = None):
        self.trial_id = registration["trial_id"]
        self._capability = registration["capability"]
        self._metadata = registration["provider"]
        self.sequence = 0
        self.transport = transport
        self.pending: list = []

    @property
    def metadata(self) -> dict:
        return copy.deepcopy(self._metadata)

    async def request(self, path: str, value: dict, schema):
        if path not in {"/infer", "/tool"}:
            raise ProviderError("invalid_broker_rpc_path")
        try:
            async with httpx.AsyncClient(
                transport=self.transport, trust_env=False, follow_redirects=False, timeout=15,
            ) as client:
                async with client.stream(
                    "POST", DATA_URL + path, json=value,
                    headers={"Authorization": f"Bearer {self._capability}"},
                ) as reply:
                    data = bytearray()
                    async for chunk in reply.aiter_bytes():
                        if len(data) + len(chunk) > 131072:
                            raise ProviderError("broker_response_too_large")
                        data.extend(chunk)
                    if reply.status_code != 200:
                        # Do not echo arbitrary broker/upstream text into reports.
                        raise ProviderError(f"broker_rpc_status:{reply.status_code}")
            return schema.model_validate_json(data)
        except (httpx.HTTPError, ValidationError):
            raise ProviderError("broker_transport_or_schema_failure") from None

    async def complete(self, messages: list[dict], tools: list[dict],
                       max_output_tokens: int) -> ModelTurn:
        turn = await self.request("/infer", {
            "sequence": self.sequence, "request_hash": digest({"messages": messages, "tools": tools}),
            "max_output_tokens": max_output_tokens,
        }, ModelTurn)
        self.sequence += 1
        self.pending = list(turn.tool_calls)
        return turn

    async def invoke(self, call: Call) -> Reply:
        if (
            not self.pending or self.pending[0].name != call.action.tool
            or self.pending[0].arguments != call.action.arguments
        ):
            raise ProviderError("tool_not_proposed")
        proposal_id = self.pending.pop(0).id
        return await self.request("/tool", {
            "model_tool_id": proposal_id, "call": call.model_dump(),
        }, Reply)


async def execute_registration(registration: dict,
                               transport: httpx.AsyncBaseTransport | None = None) -> dict:
    proxy = RPCProvider(registration, transport)
    return await ToolCallingAdapter(proxy).execute(
        registration["trial_id"], registration["task"],
        Budget.model_validate(registration["budget"]), proxy.invoke,
    )


def reconcile(row: dict, observed: dict) -> dict:
    row["adapter_observation"] = observed
    try:
        validated = Observation.model_validate(observed).model_dump()
    except ValidationError:
        row["errors"].append("missing_or_malformed_adapter_evidence")
    else:
        if any(validated[key] != row[key] for key in ("turns", "transcript", "usage", "finished")):
            row["errors"].append("adapter_broker_evidence_conflict")
        row["errors"].extend(e for e in validated["errors"] if e not in row["errors"])
    task = load_task()
    row["evaluation"] = evaluate_trial(task, row, task.fixture(row["condition"]))
    return row


async def run_rpc_mechanics(output, budget: Budget) -> dict:
    from lab.counterfactual import (
        CONDITIONS, DeterministicFakeProvider, write_trial_reports,
    )

    output.mkdir(parents=True, exist_ok=False)
    (output / "trials").mkdir()
    manager = Broker(DeterministicFakeProvider(), secrets.token_urlsafe(32), budget)
    data_app, control_app = manager.apps()
    trials = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_app), base_url=CONTROL_URL,
        headers={"Authorization": f"Bearer {manager.control_token}"}, trust_env=False,
    ) as control:
        for repeat in range(1, budget.trials_per_condition + 1):
            for condition in CONDITIONS[repeat % 4:] + CONDITIONS[:repeat % 4]:
                reply = await control.post("/trials", json={"condition": condition, "repeat": repeat})
                reply.raise_for_status()
                registration = reply.json()
                observed = await execute_registration(
                    registration, httpx.ASGITransport(app=data_app),
                )
                final = await control.post(f"/trials/{registration['trial_id']}")
                final.raise_for_status()
                row = reconcile(final.json(), observed)
                trials.append(row)
                (output / "trials" / f"{row['trial_id']}.json").write_text(
                    json.dumps(row, indent=2) + "\n", encoding="utf-8",
                )
    return write_trial_reports(
        output, budget, trials, manager.provider.metadata,
        {"mode": "asgi_rpc_fake_mechanics", "verified": False,
         "warning": "HTTP RPC routing exercised in-process, not Linux/network/live-model proof."},
    )


def main():
    """Container-side entrypoint: registration arrives only over the supervisor's stdin."""
    import sys

    registration = json.loads(sys.stdin.buffer.read(MAX_BODY + 1))
    print(json.dumps(asyncio.run(execute_registration(registration)), ensure_ascii=True))


if __name__ == "__main__":
    main()
