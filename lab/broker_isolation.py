"""Separate counterfactual profile. Does not alter the original five-container rules."""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time

import httpx
from pydantic import ValidationError
import uvicorn

from lab.adapters.tool_calling import Budget
from lab.broker_rpc import Broker, CONTROL_URL, DATA_URL, UpstreamConfig, reconcile
from lab.contracts import digest
from lab.counterfactual import DeterministicFakeProvider, summarize_trials
from lab.isolated_component import source_hash
from lab.isolation import IsolationError, Supervisor, command, podman, preflight
from lab.isolation_policy import container_options, stable_nft

SUBNET = "10.203.44.0/24"
ADAPTER = "10.203.44.10"
BROKER = "10.203.44.1"
REQUIRED = {
    "broker_rpc", "broker_control_denied", "deny_host", "deny_direct_services", "deny_capture",
    "deny_management", "deny_egress", "deny_ipv6", "deny_dns", "deny_provider_secret",
    "broker_control_over_data",
}


def adapter_policy() -> str:
    return (
        "table inet boundary_lab {\n counter denied_output {}\n"
        " chain input { type filter hook input priority -150; policy drop;\n"
        '  iifname "lo" accept\n  ct state established,related accept\n }\n'
        " chain output { type filter hook output priority -150; policy drop;\n"
        '  oifname "lo" accept\n  ct state established,related accept\n'
        f"  ip saddr {ADAPTER} ip daddr {BROKER} tcp dport 8000 ct state new accept\n"
        "  counter name denied_output reject with icmpx type admin-prohibited\n }\n}\n"
    )


def profile() -> dict:
    return {
        "name": "counterfactual-broker-v1", "subnet": SUBNET, "adapter": ADAPTER,
        "trusted_host_broker": BROKER, "data_url": DATA_URL, "control_url": CONTROL_URL,
        "adapter_policy": adapter_policy(),
        "credentials": "trusted host process only; no container secrets, volumes or engine sockets",
        "upstream": "trusted host HTTPS client, exact configured endpoint allowlist, no redirects",
        "tool_state": "trusted broker synthetic workspace/capture, never adapter-owned evidence",
    }


def proof_complete(evidence: dict) -> bool:
    return (
        evidence.get("profile_hash") == digest(profile())
        and {p.get("name") for p in evidence.get("probes", [])} == REQUIRED
        and len(evidence.get("probes", [])) == len(REQUIRED)
        and all(p.get("passed") is True for p in evidence["probes"])
        and set(evidence.get("checks", {})) == {
            "platform", "config", "source", "policy_readback", "default_routes",
        }
        and all(v is True for v in evidence["checks"].values())
    )


def _serve(stop, control_token: str, budget: dict, config: dict | None, credential: str):
    # This process runs on the trusted host; no credential is forwarded to Podman.
    provider = (
        UpstreamConfig.model_validate(config).provider(credential)
        if config is not None else DeterministicFakeProvider()
    )
    apps = Broker(provider, control_token, Budget.model_validate(budget)).apps()

    async def serve():
        servers = [
            uvicorn.Server(uvicorn.Config(
                app, host=host, port=port, log_level="error", access_log=False,
                timeout_graceful_shutdown=2,
                limit_concurrency=8, h11_max_incomplete_event_size=16384,
            ))
            for app, host, port in zip(apps, (BROKER, "127.0.0.1"), (8000, 9000), strict=True)
        ]

        async def watch():
            while not stop.is_set():
                await asyncio.sleep(.05)
            for server in servers:
                server.should_exit = True

        async with asyncio.TaskGroup() as group:
            group.create_task(watch())
            for server in servers:
                group.create_task(server.serve())
    asyncio.run(serve())


class BrokerSupervisor(Supervisor):
    def __init__(self, image: str, output: Path, budget: Budget):
        super().__init__(image, output)
        self.budget = budget
        self.names = {"adapter": f"{self.prefix}-adapter"}
        self.network_names = {"broker": f"{self.prefix}-broker"}
        self.control_token = secrets.token_urlsafe(32)
        self.server = None
        self.stop_event = None
        self.evidence.update(
            scope="counterfactual broker isolation, deterministic fake inference only",
            topology=profile(), profile_hash=digest(profile()), source_hash=source_hash(),
        )

    def prepare(self):
        for route in json.loads(command(["ip", "-j", "route", "show", "table", "all"])):
            destination = route.get("dst", "")
            if destination not in {"default", ""}:
                existing = ipaddress.ip_network(destination, strict=False)
                if existing.version == 4 and existing.overlaps(ipaddress.ip_network(SUBNET)):
                    raise IsolationError("Broker subnet overlaps an existing host route")
        name = self.network_names["broker"]
        podman("network", "create", "--internal", "--disable-dns", "--subnet", SUBNET, name)
        self.networks.append(name)
        network = json.loads(podman("network", "inspect", name))[0]
        interface = network.get("network_interface", "")
        if (
            network.get("internal") is not True or network.get("dns_enabled") is not False
            or network.get("driver") != "bridge" or network.get("ipv6_enabled") is not False
            or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", interface)
        ):
            raise IsolationError("Unexpected owned broker bridge")
        addresses = json.loads(command(["ip", "-j", "address", "show", "dev", interface]))
        assigned = [a["local"] for n in addresses for a in n.get("addr_info", [])]
        if BROKER not in assigned:
            command(["ip", "address", "add", BROKER + "/24", "dev", interface])
        options = container_options("adapter", self.image, self.names["adapter"])
        options += ["--network", f"{name}:ip={ADAPTER}", self.image, "start", "runner"]
        podman(*options)
        self.containers.append(self.names["adapter"])
        self.inspect_config("adapter", self.output, {"broker": ADAPTER})
        if self.exec("adapter", "source")["source_hash"] != source_hash():
            raise IsolationError("Image source differs from broker supervisor source")
        text = adapter_policy()
        self.ns("adapter", "nft", "--check", "--file", "-", data=text)
        self.ns("adapter", "nft", "--file", "-", data=text)
        actual = json.loads(self.ns("adapter", "nft", "-j", "list", "table", "inet", "boundary_lab"))
        chains = [row["chain"] for row in actual["nftables"] if "chain" in row]
        if {c["name"] for c in chains} != {"input", "output"} or any(
            c.get("policy") != "drop" or c.get("prio") != -150 for c in chains
        ):
            raise IsolationError("Broker namespace policy readback mismatch")
        self.policy_baseline["adapter"] = stable_nft(actual)
        self.evidence["policies"]["adapter"] = {
            "generated": text, "installed": actual, "hash": hashlib.sha256(text.encode()).hexdigest(),
        }
        self.ns("adapter", "ip", "route", "replace", "default", "via", BROKER)
        routes = json.loads(self.ns("adapter", "ip", "-j", "route", "show", "default"))
        if len(routes) != 1 or routes[0].get("gateway") != BROKER:
            raise IsolationError("Missing controlled broker default route")
        self.evidence["checks"] = dict.fromkeys((
            "platform", "config", "source", "policy_readback", "default_routes",
        ), True)
        podman(
            "exec", self.names["adapter"], "/app/.venv/bin/python", "-c",
            "from pathlib import Path; Path('/tmp/policy-ready').touch()",
        )

    def start_server(self, config: UpstreamConfig | None = None, credential: str = ""):
        if config is not None and not proof_complete(self.evidence):
            raise IsolationError("Fresh actual changed-profile proof required before live startup")
        for address, port in ((BROKER, 8000), ("127.0.0.1", 9000)):
            with socket.socket() as check:
                check.bind((address, port))
        context = multiprocessing.get_context("spawn")
        self.stop_event = context.Event()
        self.server = context.Process(
            target=_serve, args=(self.stop_event, self.control_token, self.budget.model_dump(),
                                 config.model_dump() if config else None, credential),
            name=f"{self.prefix}-trusted-broker",
        )
        self.server.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not self.server.is_alive():
                raise IsolationError("Trusted broker process exited during startup")
            try:
                status = self.control("GET", "/status")
                expected = (
                    config.provider(credential).metadata
                    if config else DeterministicFakeProvider().metadata
                )
                if status != {"ready": True, "provider": expected}:
                    raise IsolationError("Trusted broker readiness identity mismatch")
                return
            except httpx.TransportError:
                time.sleep(.1)
        raise IsolationError("Trusted broker startup timed out")

    def stop_server(self):
        if self.server is not None:
            if self.server.pid is None:
                self.server = None
                return
            self.stop_event.set()
            self.server.join(5)
            if self.server.is_alive():
                self.server.terminate()
                self.server.join(3)
            if self.server.is_alive():
                raise IsolationError("Task-owned trusted broker did not stop")
            self.server = None

    def control(self, method: str, path: str, value: dict | None = None) -> dict:
        with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as client:
            reply = client.request(
                method, CONTROL_URL + path, json=value,
                headers={"Authorization": f"Bearer {self.control_token}"},
            )
            reply.raise_for_status()
            return reply.json()

    def matrix(self) -> list[dict]:
        from lab.counterfactual import CONDITIONS

        rows = []
        for repeat in range(1, self.budget.trials_per_condition + 1):
            for condition in CONDITIONS[repeat % 4:] + CONDITIONS[:repeat % 4]:
                registration = self.control("POST", "/trials", {
                    "condition": condition, "repeat": repeat,
                })
                # Revalidate namespace/PID continuity before the adapter starts.
                self.exec("adapter", "source")
                try:
                    observed = json.loads(podman(
                        "exec", "--interactive", self.names["adapter"],
                        "/app/.venv/bin/python", "-m", "lab.broker_rpc",
                        data=json.dumps(registration) + "\n",
                        timeout=self.budget.trial_timeout_seconds + 10,
                    ))
                except (IsolationError, subprocess.TimeoutExpired, ValueError):
                    observed = {"errors": ["adapter_process_or_output_failure"]}
                deadline = time.monotonic() + self.budget.call_timeout_seconds + 2
                while True:
                    try:
                        row = self.control("POST", f"/trials/{registration['trial_id']}")
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code != 409 or time.monotonic() >= deadline:
                            raise
                        time.sleep(.1)
                row = reconcile(row, observed)
                rows.append(row)
                (self.output / f"trial-{row['trial_id']}.json").write_text(
                    json.dumps(row, indent=2) + "\n", encoding="utf-8",
                )
        return rows

    def prove(self):
        self.start_server()
        rows = self.matrix()
        self.evidence["mechanics_trials"] = rows
        self.evidence["probes"].append({
            "name": "broker_rpc", "passed": all(
                r["evaluation"]["status"] == "completed" and r["evaluation"]["task_completed"]
                and r["evaluation"]["unsafe_capture_effect"] == (
                    r["condition"] in {"injected", "unrelated_edit"}
                ) for r in rows
            ),
        })
        control = self.exec("adapter", "probe", "broker-control")
        self.evidence["probes"].append({
            "name": "broker_control_over_data", "result": control,
            "passed": control == {"status": 404},
        })
        for name, address, port in (
            ("broker_control_denied", BROKER, 9000),
            ("deny_direct_services", "10.203.42.11", 8000),
            ("deny_capture", "10.203.43.11", 8000),
            ("deny_management", "10.203.40.12", 9000),
            ("deny_egress", "192.0.2.1", 443),
        ):
            self.deny(name, address, port)
        self.deny("deny_ipv6", "2001:db8::1", 443, route_ipv6=True)
        route = json.loads(command(["ip", "-j", "route", "get", "192.0.2.1"]))[0]
        host = route.get("prefsrc") or route.get("src")
        if not host or not ipaddress.ip_address(host).is_private:
            raise IsolationError("Missing private host address")
        with socket.socket() as canary:
            canary.bind((host, 0))
            canary.listen(2)
            with socket.create_connection(canary.getsockname(), timeout=1):
                conn, _ = canary.accept()
                conn.close()
            self.deny("deny_host", host, canary.getsockname()[1])
        before = self.counter()
        dns = self.exec("adapter", "probe", "dns")
        self.evidence["probes"].append({
            "name": "deny_dns", "result": dns, "counter_before": before,
            "counter_after": self.counter(),
            "passed": dns["received"] is False and self.counter() > before,
        })
        absent = json.loads(podman(
            "exec", self.names["adapter"], "/app/.venv/bin/python", "-c",
            "import os,json; from pathlib import Path; print(json.dumps({"
            "'env':any(k.startswith('LAB_PROVIDER_') for k in os.environ),"
            "'mount':bool(list(Path('/run/secrets').glob('*')))}))",
        ))
        self.evidence["probes"].append({
            "name": "deny_provider_secret", "result": absent,
            "passed": absent == {"env": False, "mount": False},
        })
        self.verify_policy()
        if not proof_complete(self.evidence):
            raise IsolationError("Changed broker profile proof missing/failed")
        self.stop_server()

    def verify_policy(self):
        actual = json.loads(self.ns("adapter", "nft", "-j", "list", "table", "inet", "boundary_lab"))
        if stable_nft(actual) != self.policy_baseline["adapter"]:
            raise IsolationError("Broker namespace policy changed")
        self.evidence["policies"]["adapter"]["after_probes"] = actual

    def cleanup(self):
        failed = False
        try:
            self.stop_server()
        except IsolationError:
            self.evidence["errors"].append("trusted_broker_cleanup_failed")
            failed = True
        finally:
            super().cleanup()
            if failed:
                self.evidence["cleanup"] = False


def main():
    parser = argparse.ArgumentParser(description="New native Linux broker profile proof/live gate")
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--upstream-config", type=Path)
    parser.add_argument("--approved-live-inference", action="store_true")
    parser.add_argument("--trials", type=int, choices=range(1, 6), default=2)
    parser.add_argument("--max-model-calls", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--max-tool-calls", type=int, choices=range(1, 13), default=6)
    parser.add_argument("--max-output-tokens", type=int, default=384)
    parser.add_argument("--max-reported-tokens", type=int, default=12000)
    args = parser.parse_args()
    config, credential = None, ""
    if args.upstream_config:
        if not args.approved_live_inference:
            parser.error("Live endpoint configuration requires explicit inference/spend approval")
        try:
            config = UpstreamConfig.model_validate_json(args.upstream_config.read_bytes())
            credential = os.environ.get(config.credential_env, "")
            # Only validation: no network request and no engine mutation.
            config.provider(credential)
        except (OSError, ValueError, ValidationError):
            parser.error(
                "Invalid upstream configuration or missing authorized host credential. "
                "Use an exact approved HTTPS endpoint/model and environment-held credential only."
            )
    elif args.approved_live_inference:
        parser.error("No live upstream configuration supplied")
    try:
        budget = Budget(
            trials_per_condition=args.trials, max_model_calls=args.max_model_calls,
            max_tool_calls=args.max_tool_calls, max_output_tokens=args.max_output_tokens,
            max_reported_tokens=args.max_reported_tokens,
        )
    except ValidationError:
        parser.error("Invalid bounded trial/model/tool/token budget")
    if (
        args.output.exists() or not args.output.parent.is_dir()
        or args.output.parent.is_symlink()
    ):
        parser.error("Output must be a NEW dedicated directory")
    args.output.mkdir(mode=0o700)
    supervisor = BrokerSupervisor(args.image, args.output.resolve(), budget)
    try:
        supervisor.evidence["preflight"] = preflight(args.image)
        supervisor.prepare()
        supervisor.prove()  # Fresh actual proof always precedes any live provider startup.
        if config:
            supervisor.start_server(config, credential)
            rows = supervisor.matrix()
            supervisor.evidence["live_trials"] = rows
            supervisor.evidence["live_summary"] = summarize_trials(rows)
            supervisor.stop_server()
            supervisor.verify_policy()
        supervisor.evidence["status"] = "proof_executed"
    except (
        IsolationError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired,
        httpx.HTTPError,
    ) as exc:
        # Cloud/provider response bodies and credentials must never enter evidence.
        supervisor.evidence["errors"].append(f"broker_profile_failure:{type(exc).__name__}")
        supervisor.evidence["status"] = "blocked_or_failed"
    finally:
        supervisor.cleanup()
        supervisor.evidence["verified"] = (
            supervisor.evidence["status"] == "proof_executed"
            and supervisor.evidence["cleanup"] is True and not supervisor.evidence["errors"]
            and proof_complete(supervisor.evidence)
        )
        (args.output / "broker-isolation-proof.json").write_text(
            json.dumps(supervisor.evidence, indent=2) + "\n", encoding="utf-8",
        )
        if "live_trials" in supervisor.evidence:
            from lab.counterfactual import write_trial_reports
            report_directory = args.output / "live-report"
            report_directory.mkdir()
            write_trial_reports(
                report_directory, supervisor.budget, supervisor.evidence["live_trials"],
                supervisor.evidence["live_trials"][0]["provider"],
                {"mode": "native_linux_broker_profile", "verified": supervisor.evidence["verified"],
                 "profile_hash": digest(profile()), "image": args.image,
                 "proof": "../broker-isolation-proof.json"},
            )
    print(json.dumps({
        "verified": supervisor.evidence["verified"], "status": supervisor.evidence["status"],
        "evidence": str(args.output / "broker-isolation-proof.json"),
    }))
    if not supervisor.evidence["verified"] or any(
        row["evaluation"]["status"] != "completed"
        for row in supervisor.evidence.get("live_trials", [])
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
