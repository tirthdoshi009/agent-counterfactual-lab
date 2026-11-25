"""OCI entrypoint: idle until the trusted host installs and verifies namespace policy."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

from lab.adapters.scripted import create_app as adapter_app, mcp_http_client
from lab.capture import create_app as capture_app
from lab.contracts import ROOT, digest
from lab.control import State
from lab.gateway import create_app as gateway_app
from lab.isolation_policy import ADDRESSES
from lab.services import create_app as service_app, create_control_app


def source_hash() -> str:
    return digest({
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "lab").rglob("*.py"))
    })


def secret() -> str:
    return Path("/run/secrets/harness").read_text(encoding="utf-8")


async def serve(role: str) -> None:
    state = State()
    if role != "adapter":
        os.environ["LAB_CONTROL_TOKEN"] = secret()
    match role:
        case "adapter":
            app = adapter_app("http://10.203.41.11:8000")
        case "gateway":
            app = gateway_app(state, "http://10.203.42.11:8000", ["10.203.41.11:8000"])
        case "services":
            app = service_app(state, "http://10.203.43.11:8000")
        case "capture":
            app = capture_app(state)
        case _:
            raise ValueError("Unknown server role")

    async def health(request):
        return JSONResponse({"role": role, "source_hash": source_hash()})

    apps = [(app, 8000)]
    if role != "adapter":
        apps.append((create_control_app(state), 9000))
    for instance, _ in apps:
        instance.router.routes.insert(0, Route("/health", health))
    async with asyncio.TaskGroup() as group:
        for instance, port in apps:
            server = uvicorn.Server(uvicorn.Config(
                instance, host="0.0.0.0", port=port, log_level="warning", access_log=False,
            ))
            group.create_task(server.serve())


async def gateway_probe(transport: str, run_id: str, token: str) -> dict:
    action = {"tool": "read_document", "arguments": {"document_id": "aster-guide"}}
    call_id = f"{run_id}:probe-{transport}"
    if transport == "http":
        async with mcp_http_client(timeout=httpx.Timeout(3)) as client:
            response = await client.post(
                "http://10.203.41.11:8000/invoke",
                headers={"Authorization": f"Bearer {token}"},
                json={"run_id": run_id, "call_id": call_id, "action": action},
            )
            response.raise_for_status()
            return response.json()
    async with streamablehttp_client(
        "http://10.203.41.11:8000/mcp",
        headers={"Authorization": f"Bearer {token}"},
        httpx_client_factory=mcp_http_client, timeout=3, sse_read_timeout=3,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("lab_invoke", {
                "run_id": run_id, "call_id": call_id, **action,
            })
            if result.structuredContent is None:
                raise ValueError("Missing MCP result")
            return result.structuredContent


def connect_probe(address: str, port: int) -> dict:
    # No application bytes are sent. Supervisor requires an nft rejection counter increment.
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        try:
            connection.connect((address, port))
        except OSError as exc:
            return {"connected": False, "errno": exc.errno, "reason": str(exc)}
        return {"connected": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("role", choices=tuple(ADDRESSES))
    probe = sub.add_parser("probe")
    probe.add_argument(
        "kind", choices=[
            "connect", "gateway", "secret", "data-control", "dns", "runtime", "broker-control",
        ],
    )
    probe.add_argument("arguments", nargs="*")
    sub.add_parser("source")
    manage = sub.add_parser("management")
    manage.add_argument("operation", choices=["health", "reset", "snapshot"])
    args = parser.parse_args()
    if args.command == "source":
        print(json.dumps({"source_hash": source_hash()}))
    elif args.command == "management":
        body = json.loads(input())

        async def management():
            responses = {}
            async with mcp_http_client(timeout=httpx.Timeout(3)) as client:
                for role in ("gateway", "services", "capture"):
                    base = f"http://{ADDRESSES[role]['management']}:9000"
                    headers = {"Authorization": f"Bearer {secret()}"}
                    if args.operation == "reset":
                        response = await client.post(
                            f"{base}/control/reset", headers=headers, json=body,
                        )
                    elif args.operation == "snapshot":
                        response = await client.get(f"{base}/control/snapshot", headers=headers)
                    else:
                        response = await client.get(f"{base}/health")
                    response.raise_for_status()
                    responses[role] = response.json()
            return responses

        result = asyncio.run(management())
        if args.operation == "snapshot":
            Path("/results/proof-snapshot.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8",
            )
        print(json.dumps(result))
    elif args.command == "start":
        while not Path("/tmp/policy-ready").exists():
            time.sleep(0.1)
        if args.role == "runner":
            # Trusted runner remains idle for host-requested bounded proof/matrix commands.
            while True:
                time.sleep(60)
        else:
            asyncio.run(serve(args.role))
    elif args.kind == "connect":
        print(json.dumps(connect_probe(args.arguments[0], int(args.arguments[1]))))
    elif args.kind == "gateway":
        transport, run_id, token = json.loads(input())
        print(json.dumps(asyncio.run(gateway_probe(transport, run_id, token))))
    elif args.kind == "secret":
        print(json.dumps({"secret_exists": Path("/run/secrets/harness").exists()}))
    elif args.kind == "runtime":
        status = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
            if ":" in line
        )
        print(json.dumps({
            "uid": os.getuid(), "gid": os.getgid(),
            "cap_eff": status["CapEff"].strip(),
            "no_new_privileges": int(status["NoNewPrivs"].strip()),
            "seccomp": int(status["Seccomp"].strip()),
        }))
    elif args.kind == "dns":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(1)
            try:
                # A synthetic non-DNS datagram, to a local bridge only.
                connection.sendto(b"ABL_LOCAL_CANARY", ("10.203.41.1", 53))
                connection.recvfrom(32)
                result = {"received": True}
            except OSError as exc:
                result = {"received": False, "errno": exc.errno}
        print(json.dumps(result))
    elif args.kind == "data-control":
        async def check():
            async with mcp_http_client(timeout=httpx.Timeout(3)) as client:
                response = await client.get("http://10.203.41.11:8000/control/snapshot")
                return {"status": response.status_code}
        print(json.dumps(asyncio.run(check())))
    elif args.kind == "broker-control":
        async def broker_control():
            async with mcp_http_client(timeout=httpx.Timeout(3)) as client:
                reply = await client.post("http://10.203.44.1:8000/trials", json={})
                return {"status": reply.status_code}
        print(json.dumps(asyncio.run(broker_control())))


if __name__ == "__main__":
    main()
