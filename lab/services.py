import copy

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lab.contracts import Call, Reply
from lab.control import State, bearer, control_routes
from lab.policy import IMPLEMENTED, authorize


class SyntheticService:
    def __init__(self, state: State, capture_url: str) -> None:
        self.state = state
        self.capture_url = capture_url

    async def dispatch(self, call: Call, token: str) -> Reply:
        state = self.state
        provision = state.provision
        principal = provision.identities.get(token) if provision else None
        reason = None
        if not provision or call.run_id != provision.run_id or not principal:
            reason = "invalid_identity_or_run"
        elif any(event["call_id"] == call.call_id for event in state.audit):
            reason = "duplicate_call"
        elif len(state.audit) >= provision.max_calls:
            reason = "call_limit"
        elif provision.variant == "guarded":
            current = principal.model_copy(
                update={"role": state.workspace["principals"][principal.id]["role"]}
            )
            reason = authorize(current, call.action, state.workspace, "service")
        reply = Reply(
            run_id=call.run_id, call_id=call.call_id,
            decision="deny" if reason else "allow", reason=reason or "seeded_checks_disabled",
        )
        if reason is None:
            try:
                reply.data = await self.execute(call, token)
                if provision and provision.variant == "guarded":
                    reply.reason = "authorized"
            except (KeyError, ValueError) as exc:
                reply.decision = "error"
                reply.reason = f"invalid_tool_arguments: {exc}"
            except httpx.HTTPError as exc:
                reply.decision = "error"
                reply.reason = f"capture_transport_error: {type(exc).__name__}"
        state.audit.append({
            "layer": "service", "principal": principal.model_dump() if principal else None,
            "action": call.action.model_dump(), **reply.model_dump(),
            "checks_enabled": bool(provision and provision.variant == "guarded"),
        })
        return reply

    async def execute(self, call: Call, token: str) -> object:
        workspace = self.state.workspace
        provision = self.state.provision
        if not provision:
            raise ValueError("Run not provisioned")
        principal = provision.identities[token]
        args = call.action.arguments
        tenant = args.get("tenant", principal.tenant)
        match call.action.tool:
            case "read_document":
                doc_id = args["document_id"]
                doc = workspace["documents"][doc_id]
                return {"id": doc_id, "tenant": doc["tenant"], "body": doc["body"]}
            case "query_record":
                return {"tenant": tenant, "record": workspace["records"][tenant]}
            case "admin_action":
                entry = {"tenant": tenant, "action": "rotate_synthetic_key", "applied": True}
                workspace["admin_actions"].append({**entry, "call_id": call.call_id})
                return entry
            case "change_role":
                target, role = args["principal_id"], args["role"]
                if role not in {"reader", "admin"}:
                    raise ValueError("Invalid role")
                workspace["principals"][target]["role"] = role
                return {"principal_id": target, "role": role}
            case "tool_output":
                return copy.deepcopy(workspace["tool_outputs"][args["kind"]])
            case "unlisted_debug":
                return {"debug_record": "SYNTHETIC_UNLISTED_DEBUG"}
            case "capture":
                payload = args["payload"]
                if not isinstance(payload, str) or len(payload) > 4096:
                    raise ValueError("Capture accepts a bounded synthetic string only")
                async with httpx.AsyncClient(trust_env=False, timeout=3) as client:
                    response = await client.post(
                        f"{self.capture_url}/capture",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"run_id": call.run_id, "call_id": call.call_id, "payload": payload},
                    )
                    response.raise_for_status()
                    return response.json()
            case _:
                if call.action.tool not in IMPLEMENTED:
                    raise ValueError("Unknown tool")
                raise ValueError("Unimplemented tool")


def create_app(state: State, capture_url: str) -> Starlette:
    service = SyntheticService(state, capture_url)

    async def invoke(request: Request) -> JSONResponse:
        call = Call.model_validate(await request.json())
        reply = await service.dispatch(call, bearer(request))
        return JSONResponse(reply.model_dump())

    return Starlette(routes=[Route("/invoke", invoke, methods=["POST"])])


def create_control_app(state: State) -> Starlette:
    return Starlette(routes=control_routes(state))

