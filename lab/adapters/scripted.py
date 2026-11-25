import asyncio
from datetime import timedelta

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lab.adapters.base import AgentAdapter
from lab.contracts import Call, Job, Reply, digest


def mcp_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers=headers, timeout=timeout, auth=auth, trust_env=False, follow_redirects=False,
    )


class ScriptedAdapter(AgentAdapter):
    def __init__(self, gateway_url: str) -> None:
        self.gateway_url = gateway_url

    async def execute(self, job: Job) -> dict:
        transcript: list[dict] = []
        errors: list[str] = []
        proposals = [action.model_dump() for action in job.actions]
        if len(job.actions) > job.max_calls:
            return {"transcript": [], "errors": ["call_limit"], "proposal_hash": digest(proposals)}

        async def http_call(call: Call) -> Reply:
            async with httpx.AsyncClient(
                timeout=job.call_timeout_seconds, trust_env=False,
            ) as client:
                response = await client.post(
                    f"{self.gateway_url}/invoke", json=call.model_dump(),
                    headers={"Authorization": f"Bearer {job.token}"},
                )
                response.raise_for_status()
                return Reply.model_validate(response.json())

        async def replay(invoke) -> None:
            for index, action in enumerate(job.actions):
                call = Call(run_id=job.run_id, call_id=f"{job.run_id}:{index}", action=action)
                async with asyncio.timeout(job.call_timeout_seconds):
                    reply = await invoke(call)
                if reply.run_id != call.run_id or reply.call_id != call.call_id:
                    raise ValueError("Gateway correlation mismatch")
                transcript.append({"call": call.model_dump(), "reply": reply.model_dump()})
                if reply.decision == "error":
                    errors.append(reply.reason)

        try:
            async with asyncio.timeout(job.case_timeout_seconds):
                if job.transport == "http":
                    await replay(http_call)
                else:
                    async with streamablehttp_client(
                        f"{self.gateway_url}/mcp",
                        headers={"Authorization": f"Bearer {job.token}"},
                        timeout=timedelta(seconds=job.call_timeout_seconds),
                        sse_read_timeout=timedelta(seconds=job.call_timeout_seconds),
                        httpx_client_factory=mcp_http_client,
                    ) as (read, write, _):
                        async with ClientSession(read, write) as session:
                            await session.initialize()

                            async def mcp_call(call: Call) -> Reply:
                                result = await session.call_tool("lab_invoke", {
                                    "run_id": call.run_id, "call_id": call.call_id,
                                    **call.action.model_dump(),
                                })
                                if result.structuredContent is None:
                                    raise ValueError("Missing MCP structured reply")
                                return Reply.model_validate(result.structuredContent)

                            await replay(mcp_call)
        except (TimeoutError, httpx.HTTPError, ValueError, ExceptionGroup) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        return {"transcript": transcript, "errors": errors, "proposal_hash": digest(proposals)}


def create_app(gateway_url: str) -> Starlette:
    adapter = ScriptedAdapter(gateway_url)

    async def execute(request: Request) -> JSONResponse:
        job = Job.model_validate(await request.json())
        return JSONResponse(await adapter.execute(job))

    return Starlette(routes=[Route("/execute", execute, methods=["POST"])])
