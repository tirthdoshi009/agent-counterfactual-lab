"""Bounded loopback demonstration, explicitly not a security-isolated runtime."""

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import multiprocessing
import os
from pathlib import Path
import secrets
import socket
import time

import httpx
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

from lab.contracts import digest
from lab.report import manifest, normalized, write_reports
from lab.runner import Runner


def _worker(kind: str, sockets: list[socket.socket], stop, token: str, ready_id: str, urls: dict):
    from lab.adapters.scripted import create_app as adapter_app
    from lab.capture import create_app as capture_app
    from lab.control import State
    from lab.gateway import create_app as gateway_app
    from lab.services import create_app as service_app, create_control_app

    logging.basicConfig(level=logging.ERROR)
    if kind != "adapter":
        os.environ["LAB_CONTROL_TOKEN"] = token
    else:
        os.environ.pop("LAB_CONTROL_TOKEN", None)
    state = State()
    if kind == "adapter":
        app = adapter_app(urls["gateway"])
    elif kind == "capture":
        app = capture_app(state)
    elif kind == "services":
        app = service_app(state, urls["capture"])
    elif kind == "gateway":
        app = gateway_app(state, urls["services"], ["127.0.0.1:*"])
    else:
        raise ValueError(f"Unknown component: {kind}")

    async def health(request):
        return JSONResponse({"component": kind, "ready_id": ready_id})

    apps = [app] if kind == "adapter" else [app, create_control_app(state)]
    for instance in apps:
        instance.router.routes.insert(0, Route("/health", health))

    async def serve():
        servers = [
            uvicorn.Server(uvicorn.Config(
                instance, host="127.0.0.1", log_level="error", access_log=False,
                timeout_graceful_shutdown=2,
            )) for instance in apps
        ]

        async def watch_stop():
            while not stop.is_set():
                await asyncio.sleep(0.05)
            for server in servers:
                server.should_exit = True

        async with asyncio.TaskGroup() as group:
            group.create_task(watch_stop())
            for server, listener in zip(servers, sockets, strict=True):
                group.create_task(server.serve(sockets=[listener]))

    asyncio.run(serve())


class LocalSimulation:
    def __init__(self):
        self.context = multiprocessing.get_context("spawn")
        self.stop = self.context.Event()
        self.processes = []
        self.listeners = []
        self.control_token = secrets.token_urlsafe(32)
        self.urls = {}
        self.control_urls = {}
        self.ready_ids = {}

    def listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        self.listeners.append(listener)
        return listener

    @asynccontextmanager
    async def running(self):
        component_sockets = {}
        try:
            for kind in ("capture", "services", "gateway", "adapter"):
                listeners = [self.listener()]
                self.urls[kind] = f"http://127.0.0.1:{listeners[0].getsockname()[1]}"
                if kind != "adapter":
                    listeners.append(self.listener())
                    self.control_urls[kind] = f"http://127.0.0.1:{listeners[1].getsockname()[1]}"
                component_sockets[kind] = listeners
                self.ready_ids[kind] = secrets.token_hex(16)
            for kind, listeners in component_sockets.items():
                process = self.context.Process(
                    target=_worker,
                    args=(kind, listeners, self.stop,
                          self.control_token if kind != "adapter" else "",
                          self.ready_ids[kind], self.urls),
                    name=f"boundary-lab-{kind}",
                )
                process.start()
                self.processes.append(process)
            deadline = time.monotonic() + 20
            async with httpx.AsyncClient(timeout=1, trust_env=False) as client:
                pending = set(self.urls)
                while pending:
                    if any(not p.is_alive() for p in self.processes):
                        raise RuntimeError("A local simulation component exited during startup")
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Simulation startup timed out: {sorted(pending)}")
                    for kind in list(pending):
                        try:
                            response = await client.get(f"{self.urls[kind]}/health")
                            if response.json() != {
                                "component": kind, "ready_id": self.ready_ids[kind]
                            }:
                                raise RuntimeError(f"{kind}: unexpected server identity")
                            response.raise_for_status()
                            pending.remove(kind)
                        except httpx.TransportError:
                            await asyncio.sleep(0.05)
            endpoints = {**self.control_urls, "adapter": self.urls["adapter"]}
            yield Runner(endpoints, self.control_token)
        finally:
            self.stop.set()
            for process in self.processes:
                await asyncio.to_thread(process.join, 6)
                if process.is_alive():
                    # Only this explicitly tracked child PID is terminated.
                    process.terminate()
                    await asyncio.to_thread(process.join, 3)
                if process.is_alive():
                    raise RuntimeError(f"Could not stop task-owned process {process.pid}")
            for listener in self.listeners:
                listener.close()


async def simulate(output: Path, repeats: int = 2) -> dict:
    if not 1 <= repeats <= 3:
        raise ValueError("Simulation repeats must be between 1 and 3")
    output.mkdir(parents=True, exist_ok=True)
    isolation = {
        "mode": "local_simulation",
        "container_validated": False,
        "host_network_isolation_verified": False,
        "binding": "127.0.0.1",
        "outbound_targets": "numeric loopback HTTP/MCP and local synthetic capture only",
        "warning": "Local processes are NOT security-isolated; no container enforcement claim.",
    }
    reports = []
    async with LocalSimulation().running() as runner:
        metadata = manifest(runner.raw_suite, runner.fixture, isolation)
        for index in range(repeats):
            executions = await runner.run(["vulnerable", "guarded"], ["http", "mcp"])
            reports.append(write_reports(output / f"repeat-{index + 1}", metadata, executions))
    hashes = [digest(normalized(report["executions"])) for report in reports]
    failed = sum(
        execution["evaluation"]["status"] != "completed"
        or (
            execution["evaluation"]["attack_success"] != (execution["variant"] == "vulnerable")
            if execution["adversarial"] else not execution["evaluation"]["benign_success"]
        )
        for report in reports for execution in report["executions"]
    )
    result = {
        "mode": "local_simulation", "isolation": isolation, "repeats": repeats,
        "executions": sum(len(report["executions"]) for report in reports),
        "summary": reports[0]["summary"],
        "normalized_hashes": hashes,
        "repeatable": len(set(hashes)) == 1,
        "unexpected_or_inconclusive": failed,
        "task_owned_processes_stopped": True,
    }
    (output / "simulation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result

