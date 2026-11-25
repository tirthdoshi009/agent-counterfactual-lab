"""Trusted native-Linux supervisor. No runtime downloads, remote engine or fallback."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import time

from lab.contracts import ROOT, digest, load_json
from lab.isolated_component import source_hash
from lab.isolation_policy import (
    ADDRESSES, NETWORKS, ROLES, all_capabilities_dropped, container_options, nft_policy,
    proof_complete, runtime_hardened, stable_nft, topology,
)


class IsolationError(RuntimeError):
    pass


def immutable_image_id(value: str) -> str:
    bare = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", bare):
        raise IsolationError("Invalid engine image identity")
    return f"sha256:{bare}"


def command(args: list[str], data: str | None = None, timeout: int = 30) -> str:
    # Do not forward cloud credentials, proxy settings or remote Podman connection variables.
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": "/root", "LANG": "C.UTF-8"}
    completed = subprocess.run(
        args, input=data, text=True, capture_output=True, timeout=timeout, env=environment,
    )
    if completed.returncode:
        # Stderr only: stdin may contain run-scoped synthetic credentials.
        raise IsolationError(f"{args[0]} failed ({completed.returncode}): {completed.stderr[:2000]}")
    return completed.stdout + completed.stderr if "logs" in args else completed.stdout


def podman(*args: str, data: str | None = None, timeout: int = 30) -> str:
    return command(["podman", "--remote=false", *args], data, timeout)


def validate_platform(system: str, uid: int, tools: dict, info: dict) -> None:
    if system != "Linux" or uid != 0:
        raise IsolationError("Requires an approved native Linux host and rootful local Podman")
    if not all(tools.get(name) for name in ("podman", "nsenter", "nft", "ip")):
        raise IsolationError("Requires host-installed podman, nsenter, nft and ip")
    host = info.get("host", {})
    security = host.get("security", {})
    if (
        host.get("os") != "linux"
        or security.get("rootless") is not False
        or security.get("seccompEnabled") is not True
        or host.get("cgroupVersion") != "v2"
        or host.get("networkBackend") != "netavark"
        or not str(info.get("version", {}).get("Version", "")).startswith("5.")
    ):
        raise IsolationError("Supported profile: Podman 5, rootful, netavark, cgroup v2, seccomp")


def preflight(image: str) -> dict:
    system = platform.system()
    uid = os.geteuid() if hasattr(os, "geteuid") else -1
    tools = {name: shutil.which(name) for name in ("podman", "nsenter", "nft", "ip")}
    # Reject unsupported hosts before executing any engine or namespace command.
    if system != "Linux" or uid != 0 or not all(tools.values()):
        validate_platform(system, uid, tools, {})
    info = json.loads(podman("info", "--format=json"))
    validate_platform(system, uid, tools, info)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise IsolationError("--image must be a locally built immutable sha256 image ID")
    image_info = json.loads(podman("image", "inspect", image))[0]
    if immutable_image_id(image_info["Id"]) != image:
        raise IsolationError("Image identity mismatch")
    for route in json.loads(command(["ip", "-j", "route", "show", "table", "all"])):
        destination = route.get("dst", "")
        if destination in {"default", ""}:
            continue
        try:
            existing = ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise IsolationError(f"Unrecognized host route {destination}") from exc
        if existing.version == 4 and any(
            existing.overlaps(ipaddress.ip_network(subnet)) for subnet in NETWORKS.values()
        ):
            raise IsolationError(f"Lab subnet conflicts with host route: {destination}")
    return {
        "platform": system, "podman": info["version"], "security": info["host"]["security"],
        "image": immutable_image_id(image_info["Id"]), "image_digests": image_info.get("RepoDigests", []),
        "architecture": image_info.get("Architecture"), "tools": tools,
    }


class Supervisor:
    def __init__(self, image: str, output: Path):
        self.image = image
        self.output = output
        self.prefix = f"abl-{secrets.token_hex(6)}"
        self.names = {role: f"{self.prefix}-{role}" for role in ROLES}
        self.network_names = {key: f"{self.prefix}-{key}" for key in NETWORKS}
        self.containers: list[str] = []
        self.networks: list[str] = []
        self.secret_name: str | None = None
        self.pids: dict[str, int] = {}
        self.policy_baseline: dict[str, str] = {}
        self.evidence = {
            "verified": False, "status": "unverified", "scope": "synthetic isolation prerequisite",
            "topology": topology(), "checks": {}, "probes": [], "errors": [],
            "policies": {}, "containers": {}, "cleanup": False,
        }

    def exec(self, role: str, *args: str, body: object | None = None) -> dict:
        if role in self.policy_baseline:
            current = json.loads(self.ns(
                role, "nft", "-j", "list", "table", "inet", "boundary_lab",
            ))
            if stable_nft(current) != self.policy_baseline[role]:
                raise IsolationError("Refusing execution in changed or restarted policy namespace")
        return json.loads(podman(
            "exec", "--interactive", self.names[role],
            "/app/.venv/bin/python", "-m", "lab.isolated_component", *args,
            data=json.dumps(body) + "\n" if body is not None else None,
        ))

    def ns(self, role: str, *args: str, data: str | None = None) -> str:
        current = json.loads(podman("inspect", self.names[role]))[0]["State"]
        if not current["Running"] or current["Pid"] != self.pids[role]:
            raise IsolationError("Container stopped/restarted; policy namespace identity is stale")
        return command(
            ["nsenter", "--target", str(self.pids[role]), "--net", "--", *args], data,
        )

    def counter(self) -> int:
        value = json.loads(self.ns("adapter", "nft", "-j", "list", "counter",
                                  "inet", "boundary_lab", "denied_output"))
        counters = [entry["counter"] for entry in value["nftables"] if "counter" in entry]
        if len(counters) != 1:
            raise IsolationError("Missing namespace rejection counter")
        return counters[0]["packets"]

    def prepare(self) -> None:
        for key, subnet in NETWORKS.items():
            name = self.network_names[key]
            podman(
                "network", "create", "--internal", "--disable-dns", "--subnet", subnet, name,
            )
            self.networks.append(name)
            net = json.loads(podman("network", "inspect", name))[0]
            if (
                net.get("internal") is not True or net.get("dns_enabled") is not False
                or net.get("driver") != "bridge" or net.get("ipv6_enabled") is not False
            ):
                raise IsolationError("Unexpected Podman network configuration")
        token = secrets.token_urlsafe(32)
        self.secret_name = f"{self.prefix}-harness"
        podman("secret", "create", self.secret_name, "-", data=token)
        results = self.output / "runner-results"
        results.mkdir(mode=0o700)
        os.chown(results, 10001, 10001)
        for role in ROLES:
            members = ADDRESSES[role]
            first = next(iter(members))
            args = container_options(
                role, self.image, self.names[role],
                self.secret_name if role != "adapter" else None,
            )
            args += ["--network", f"{self.network_names[first]}:ip={members[first]}"]
            if role == "runner":
                args += ["--volume", f"{results}:/results:rw,Z"]
            args += [self.image, "start", role]
            podman(*args)
            self.containers.append(self.names[role])
            for network, address in list(members.items())[1:]:
                podman(
                    "network", "connect", "--ip", address,
                    self.network_names[network], self.names[role],
                )
            self.inspect_config(role, results)
            actual = self.exec(role, "source")["source_hash"]
            if actual != source_hash():
                raise IsolationError("Image source differs from trusted supervisor source")
        self.evidence["checks"].update(platform=True, config=True, source=True)
        # Components are still idle: install policies before any app accepts requests.
        for role in ROLES:
            policy = nft_policy(role)
            self.ns(role, "nft", "--check", "--file", "-", data=policy)
            self.ns(role, "nft", "--file", "-", data=policy)
            actual = json.loads(self.ns(role, "nft", "-j", "list", "table", "inet", "boundary_lab"))
            chains = [entry["chain"] for entry in actual["nftables"] if "chain" in entry]
            if (
                {chain["name"] for chain in chains} != {"input", "output"}
                or any(chain["policy"] != "drop" or chain["prio"] != -150 for chain in chains)
            ):
                raise IsolationError("Namespace policy readback is not deny-by-default")
            self.policy_baseline[role] = stable_nft(actual)
            self.evidence["policies"][role] = {
                "generated": policy, "installed": actual,
                "hash": hashlib.sha256(policy.encode()).hexdigest(),
            }
            # Ensure denial probes use a route rather than passing merely due to no route.
            first = next(iter(ADDRESSES[role]))
            bridge = str(ipaddress.ip_network(NETWORKS[first]).network_address + 1)
            self.ns(role, "ip", "route", "replace", "default", "via", bridge)
            routes = json.loads(self.ns(role, "ip", "-j", "route", "show", "default"))
            if len(routes) != 1 or routes[0].get("gateway") != bridge:
                raise IsolationError("Missing controlled default route for deny probes")
        self.evidence["checks"].update(policy_readback=True, default_routes=True)
        for role in ROLES:
            podman(
                "exec", self.names[role], "/app/.venv/bin/python", "-c",
                "from pathlib import Path; Path('/tmp/policy-ready').touch()",
            )

    def inspect_config(self, role: str, results: Path,
                       members: dict[str, str] | None = None) -> None:
        info = json.loads(podman("inspect", self.names[role]))[0]
        config, host = info["Config"], info["HostConfig"]
        # Unknown/missing inspect fields fail, never silently relax this profile.
        if (
            config.get("User") != "10001:10001"
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or not any("no-new-privileges" in item for item in host.get("SecurityOpt", []))
            or host.get("CapAdd") or info.get("EffectiveCaps")
            or "EffectiveCaps" not in info
            or not all_capabilities_dropped(host.get("CapDrop", []))
            or host.get("PortBindings")
            or host.get("PidMode") == "host" or host.get("IpcMode") == "host"
            or host.get("PidsLimit") != 96
            or host.get("Memory") != 384 * 1024 * 1024
            or host.get("NanoCpus") != 1_000_000_000
        ):
            raise IsolationError(f"{role}: container hardening inspect mismatch")
        attachments = info["NetworkSettings"]["Networks"]
        expected = {
            self.network_names[network]: ip for network, ip in (
                ADDRESSES[role] if members is None else members
            ).items()
        }
        if (
            set(attachments) != set(expected)
            or any(attachments[name]["IPAddress"] != address for name, address in expected.items())
        ):
            raise IsolationError(f"{role}: topology inspect mismatch")
        binds = [mount for mount in info.get("Mounts", []) if mount["Type"] in {"bind", "volume"}]
        # Podman secrets may be represented as secret mounts or a dedicated read-only bind.
        safe = [
            mount for mount in binds
            if role != "adapter" and mount["Destination"] == "/run/secrets/harness"
            and mount.get("RW") is False
        ]
        remaining = [mount for mount in binds if mount not in safe]
        if role == "runner":
            if not (
                len(remaining) == 1 and remaining[0]["Destination"] == "/results"
                and Path(remaining[0]["Source"]).resolve() == results
                and remaining[0]["RW"] is True
            ):
                raise IsolationError("Runner must mount only its dedicated results directory")
        elif remaining:
            raise IsolationError(f"{role}: unexpected host/volume mount")
        self.pids[role] = info["State"]["Pid"]
        if self.pids[role] <= 0:
            raise IsolationError("Missing running container network namespace")
        self.evidence["containers"][role] = {
            "id": info["Id"], "image": info["Image"], "pid": self.pids[role],
            "user": config["User"], "hardening": host, "networks": attachments,
            "mounts": info.get("Mounts", []),
        }
        status = self.exec(role, "probe", "runtime")
        if not runtime_hardened(status):
            raise IsolationError(f"{role}: process capabilities/seccomp/user mismatch")
        self.evidence["containers"][role]["process_hardening"] = status

    def deny(self, name: str, address: str, port: int, route_ipv6: bool = False) -> None:
        if route_ipv6:
            device = json.loads(self.ns("adapter", "ip", "-j", "route", "show", "default"))[0]["dev"]
            self.ns("adapter", "ip", "-6", "addr", "add", "2001:db8:ffff::2/64", "dev", device,
                    "nodad")
            self.ns("adapter", "ip", "-6", "route", "replace", "2001:db8::/32", "dev", device)
        before = self.counter()
        result = self.exec("adapter", "probe", "connect", address, str(port))
        after = self.counter()
        self.evidence["probes"].append({
            "name": name, "target": [address, port], "result": result,
            "counter_before": before, "counter_after": after,
            "passed": result["connected"] is False and after > before,
        })

    def prove(self) -> None:
        deadline = time.monotonic() + 15
        while True:
            try:
                health = self.exec("runner", "management", "health", body={})
                if any(row["source_hash"] != source_hash() for row in health.values()):
                    raise IsolationError("Health source hash mismatch")
                break
            except IsolationError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        fixture = load_json(ROOT / "fixtures" / "workspace.json")
        run_id, identity = secrets.token_hex(16), secrets.token_urlsafe(32)
        provision = {
            "run_id": run_id, "variant": "guarded", "fixture_hash": digest(fixture), "max_calls": 4,
            "identities": {identity: fixture["principals"]["aster-reader"]},
        }
        reset = self.exec("runner", "management", "reset", body=provision)
        expected = {
            "run_id": run_id, "fixture_hash": digest(fixture),
            "workspace": fixture, "audit": [], "capture": [],
        }
        if any(row != expected for row in reset.values()):
            raise IsolationError("Proof reset not verified")
        for transport in ("http", "mcp"):
            reply = self.exec("adapter", "probe", "gateway", body=[transport, run_id, identity])
            doc = fixture["documents"]["aster-guide"]
            self.evidence["probes"].append({
                "name": f"gateway_{transport}", "reply": reply,
                "passed": reply == {
                    "run_id": run_id, "call_id": f"{run_id}:probe-{transport}",
                    "decision": "allow", "reason": "authorized",
                    "data": {"id": "aster-guide", "tenant": "aster", "body": doc["body"]},
                },
            })
        self.deny("deny_direct_services", "10.203.42.11", 8000)
        self.deny("deny_capture", "10.203.43.11", 8000)
        self.deny("deny_management", "10.203.40.12", 9000)
        self.deny("deny_same_peer_control", "10.203.41.11", 9000)
        # Positive host canary proves listener existence; no application bytes from container.
        host_route = json.loads(command(["ip", "-j", "route", "get", "192.0.2.1"]))[0]
        host_address = host_route.get("prefsrc") or host_route.get("src")
        if not host_address or not ipaddress.ip_address(host_address).is_private:
            raise IsolationError("Missing private host address for local listening canary")
        with socket.socket() as canary:
            canary.bind((host_address, 0))
            canary.listen(2)
            port = canary.getsockname()[1]
            with socket.create_connection((host_address, port), timeout=1):
                connection, _ = canary.accept()
                connection.close()
            self.deny("deny_host", host_address, port)
        # TEST-NET addresses are intercepted by OUTPUT rejection; no public endpoint contacted.
        self.deny("deny_egress", "192.0.2.1", 443)
        self.deny("deny_ipv6", "2001:db8::1", 443, route_ipv6=True)
        before = self.counter()
        dns = self.exec("adapter", "probe", "dns")
        after = self.counter()
        self.evidence["probes"].append({
            "name": "deny_dns", "result": dns, "counter_before": before, "counter_after": after,
            "passed": dns["received"] is False and after > before,
        })
        absent = self.exec("adapter", "probe", "secret")
        self.evidence["probes"].append({
            "name": "deny_harness_secret", "result": absent, "passed": absent["secret_exists"] is False,
        })
        control = self.exec("adapter", "probe", "data-control")
        self.evidence["probes"].append({
            "name": "deny_control_over_data", "result": control, "passed": control["status"] == 404,
        })
        snapshots = self.exec("runner", "management", "snapshot", body={})
        persisted = json.loads(
            (self.output / "runner-results" / "proof-snapshot.json").read_text(encoding="utf-8"),
        )
        if persisted != snapshots:
            raise IsolationError("Runner-only results mount evidence differs from control snapshots")
        self.evidence["audit_evidence"] = snapshots
        # Cross-check the two permitted reads; no state/capture mutation is permitted.
        if (
            any(row["workspace"] != fixture or row["capture"] for row in snapshots.values())
            or len(snapshots["gateway"]["audit"]) != 2
            or len(snapshots["services"]["audit"]) != 2
        ):
            raise IsolationError("Permitted-path audit/state evidence mismatch")
        for index, transport in enumerate(("http", "mcp")):
            gateway = snapshots["gateway"]["audit"][index]
            service = snapshots["services"]["audit"][index]
            expected_call = f"{run_id}:probe-{transport}"
            if (
                gateway["run_id"] != run_id or gateway["call_id"] != expected_call
                or service["run_id"] != run_id or service["call_id"] != expected_call
                or gateway["principal"] != fixture["principals"]["aster-reader"]
                or service["principal"] != gateway["principal"]
                or gateway["service_reply"] != {
                    key: service[key] for key in ("run_id", "call_id", "decision", "reason", "data")
                }
                or gateway["decision"] != "allow" or service["decision"] != "allow"
            ):
                raise IsolationError("Gateway/service proof correlation conflict")
        for role in ROLES:
            current = json.loads(self.ns(role, "nft", "-j", "list", "table", "inet", "boundary_lab"))
            if stable_nft(current) != self.policy_baseline[role]:
                raise IsolationError("Namespace policy changed during proof")
            self.evidence["policies"][role]["after_probes"] = current
        if not proof_complete(self.evidence["probes"], self.evidence["checks"]):
            raise IsolationError("Missing/failed runtime proof; isolation remains unverified")

    def cleanup(self) -> None:
        failures = []
        for name in reversed(self.containers):
            try:
                try:
                    logs = podman("logs", name)
                    (self.output / f"{name}.log").write_text(logs, encoding="utf-8")
                finally:
                    podman("rm", "--force", name)
            except (IsolationError, OSError, subprocess.TimeoutExpired) as exc:
                failures.append(str(exc))
        for network in reversed(self.networks):
            try:
                podman("network", "rm", network)
            except (IsolationError, OSError, subprocess.TimeoutExpired) as exc:
                failures.append(str(exc))
        if self.secret_name:
            try:
                podman("secret", "rm", self.secret_name)
            except (IsolationError, OSError, subprocess.TimeoutExpired) as exc:
                failures.append(str(exc))
        self.evidence["cleanup"] = not failures
        self.evidence["errors"].extend(failures)


def main() -> None:
    parser = argparse.ArgumentParser(description="Native Linux rootful Podman isolation proof")
    parser.add_argument("--image", required=True, help="Prebuilt local sha256 image ID; never pulled")
    parser.add_argument("--output", type=Path, required=True, help="New dedicated evidence directory")
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or not output.parent.is_dir() or output.parent.is_symlink():
        raise SystemExit("Output must be a NEW directory under an existing nonsymlink parent")
    output.mkdir(mode=0o700)
    supervisor = Supervisor(args.image, output.resolve())
    try:
        supervisor.evidence["preflight"] = preflight(args.image)
        supervisor.prepare()
        supervisor.prove()
        supervisor.evidence["status"] = "proof_executed"
    except (IsolationError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        supervisor.evidence["errors"].append(f"{type(exc).__name__}: {exc}")
        supervisor.evidence["status"] = "blocked_or_failed"
    finally:
        supervisor.cleanup()
        supervisor.evidence["verified"] = (
            supervisor.evidence["status"] == "proof_executed"
            and supervisor.evidence["cleanup"] is True
            and not supervisor.evidence["errors"]
            and proof_complete(supervisor.evidence["probes"], supervisor.evidence["checks"])
        )
        (output / "isolation-proof.json").write_text(
            json.dumps(supervisor.evidence, indent=2) + "\n", encoding="utf-8",
        )
    print(json.dumps({
        "verified": supervisor.evidence["verified"], "status": supervisor.evidence["status"],
        "errors": supervisor.evidence["errors"], "evidence": str(output / "isolation-proof.json"),
    }, indent=2))
    if not supervisor.evidence["verified"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
