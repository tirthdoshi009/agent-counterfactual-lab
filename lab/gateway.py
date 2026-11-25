from contextlib import asynccontextmanager
import json

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.server import Settings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from lab.contracts import Action, Call, Reply
from lab.control import State, bearer
from lab.policy import authorize, validate_result


class Gateway:
    def __init__(self, state: State, service_url: str) -> None:
        self.state = state
        self.service_url = service_url

    async def dispatch(self, call: Call, token: str) -> Reply:
        state = self.state
        provision = state.provision
        principal = provision.identities.get(token) if provision else None
        reason = None
        if not provision or not principal or call.run_id != provision.run_id:
            reason = "invalid_identity_or_run"
        elif any(event["call_id"] == call.call_id for event in state.audit):
            reason = "duplicate_call"
        elif len(state.audit) >= provision.max_calls:
            reason = "call_limit"
        elif provision.variant == "guarded":
            reason = authorize(principal, call.action, state.workspace, "gateway")
        reply = Reply(
            run_id=call.run_id, call_id=call.call_id,
            decision="deny" if reason else "allow", reason=reason or "authorized",
        )
        service_reply = None
        if not reason:
            try:
                async with httpx.AsyncClient(trust_env=False, timeout=3) as client:
                    response = await client.post(
                        f"{self.service_url}/invoke",
                        headers={"Authorization": f"Bearer {token}"},
                        json=call.model_dump(),
                    )
                    response.raise_for_status()
                    service_reply = Reply.model_validate(response.json())
                if (
                    service_reply.run_id != call.run_id
                    or service_reply.call_id != call.call_id
                ):
                    raise ValueError("Service correlation mismatch")
                reply = service_reply.model_copy(deep=True)
                if (
                    provision and provision.variant == "guarded"
                    and reply.decision == "allow"
                    and not validate_result(call.action.tool, reply.data)
                ):
                    reply.decision, reply.reason, reply.data = "deny", "invalid_tool_result", None
            except (httpx.HTTPError, ValueError) as exc:
                reply.decision = "error"
                reply.reason = f"service_error: {type(exc).__name__}: {exc}"
        state.audit.append({
            "layer": "gateway", "principal": principal.model_dump() if principal else None,
            "action": call.action.model_dump(), **reply.model_dump(),
            "checks_enabled": bool(provision and provision.variant == "guarded"),
            "service_reply": service_reply.model_dump() if service_reply else None,
        })
        return reply


def create_app(state: State, service_url: str, allowed_hosts: list[str]) -> Starlette:
    gateway = Gateway(state, service_url)
    # Resolve the SDK's lifespan forward reference before settings sources inspect it.
    Settings.model_rebuild()
    sdk = FastMCP(
        "boundary_lab_mcp", stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        ),
    )

    # The transport envelope is not an authority. Both transports enter one dispatcher.
    @sdk.tool(
        name="lab_invoke", structured_output=False,
        annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    )
    async def lab_invoke(
        run_id: str, call_id: str, tool: str, arguments: dict, ctx: Context,
        source: str = "script",
    ) -> CallToolResult:
        """Propose a named synthetic workspace action; the gateway authorizes it."""
        request = ctx.request_context.request
        if not isinstance(request, Request):
            raise ValueError("MCP tool requires an authenticated HTTP request context")
        call = Call(
            run_id=run_id, call_id=call_id,
            action=Action(tool=tool, arguments=arguments, source=source),
        )
        reply = await gateway.dispatch(call, bearer(request))
        data = reply.model_dump()
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(data))],
            structuredContent=data,
            isError=reply.decision == "error",
        )

    async def invoke(request: Request) -> JSONResponse:
        call = Call.model_validate(await request.json())
        return JSONResponse((await gateway.dispatch(call, bearer(request))).model_dump())

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with sdk.session_manager.run():
            yield

    return Starlette(
        routes=[Route("/invoke", invoke, methods=["POST"]), Mount("/", sdk.streamable_http_app())],
        lifespan=lifespan,
    )

