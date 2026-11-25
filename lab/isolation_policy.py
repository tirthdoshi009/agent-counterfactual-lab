"""Pure policy generation; generated policy alone never proves isolation."""

from dataclasses import asdict, dataclass
import ipaddress
import json
import re

ROLES = ("adapter", "gateway", "services", "capture", "runner")
DEFAULT_CAPABILITIES = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
    "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID",
    "CAP_SYS_CHROOT",
}
NETWORKS = {
    "management": "10.203.40.0/24",
    "agent": "10.203.41.0/24",
    "backend": "10.203.42.0/24",
    "capture": "10.203.43.0/24",
}
ADDRESSES = {
    "runner": {"management": "10.203.40.10"},
    "adapter": {"management": "10.203.40.11", "agent": "10.203.41.10"},
    "gateway": {
        "management": "10.203.40.12", "agent": "10.203.41.11", "backend": "10.203.42.10",
    },
    "services": {
        "management": "10.203.40.13", "backend": "10.203.42.11", "capture": "10.203.43.10",
    },
    "capture": {"management": "10.203.40.14", "capture": "10.203.43.11"},
}


@dataclass(frozen=True)
class Edge:
    source: str
    destination: str
    network: str
    port: int


EDGES = (
    Edge("adapter", "gateway", "agent", 8000),
    Edge("gateway", "services", "backend", 8000),
    Edge("services", "capture", "capture", 8000),
    Edge("runner", "adapter", "management", 8000),
    Edge("runner", "gateway", "management", 9000),
    Edge("runner", "services", "management", 9000),
    Edge("runner", "capture", "management", 9000),
)


def validate_topology() -> None:
    for role, members in ADDRESSES.items():
        if role not in ROLES:
            raise ValueError("Unknown container role")
        for network, address in members.items():
            if ipaddress.ip_address(address) not in ipaddress.ip_network(NETWORKS[network]):
                raise ValueError("Address outside declared subnet")
    for edge in EDGES:
        if (
            edge.network not in ADDRESSES[edge.source]
            or edge.network not in ADDRESSES[edge.destination]
            or not 1 <= edge.port <= 65535
        ):
            raise ValueError("Invalid policy edge")


def nft_policy(role: str) -> str:
    validate_topology()
    if role not in ROLES:
        raise ValueError("Unknown role")
    lines = [
        "table inet boundary_lab {",
        " counter denied_output {}",
        " chain input { type filter hook input priority -150; policy drop;",
        '  iifname "lo" accept',
        "  ct state established,related accept",
    ]
    for edge in EDGES:
        if edge.destination == role:
            lines.append(
                f"  ip saddr {ADDRESSES[edge.source][edge.network]} "
                f"ip daddr {ADDRESSES[role][edge.network]} tcp dport {edge.port} "
                "ct state new accept"
            )
    lines += [
        " }", " chain output { type filter hook output priority -150; policy drop;",
        '  oifname "lo" accept',
        "  ct state established,related accept",
    ]
    for edge in EDGES:
        if edge.source == role:
            lines.append(
                f"  ip saddr {ADDRESSES[role][edge.network]} "
                f"ip daddr {ADDRESSES[edge.destination][edge.network]} "
                f"tcp dport {edge.port} ct state new accept"
            )
    # No DNS, UDP, uncontrolled IPv4/IPv6, or bridge/host destinations are permitted.
    lines += [
        "  counter name denied_output reject with icmpx type admin-prohibited",
        " }", "}", "",
    ]
    return "\n".join(lines)


def container_options(role: str, image: str, name: str, secret: str | None = None) -> list[str]:
    if role not in ROLES or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Expected known role and immutable local image ID")
    if not re.fullmatch(r"abl-[a-f0-9]{12}-[a-z]+", name):
        raise ValueError("Unexpected task-owned container name")
    args = [
        "run", "--detach", "--pull=never", "--name", name,
        "--user", "10001:10001", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--pids-limit=96", "--memory=384m", "--cpus=1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--ipc=private", "--pid=private", "--uts=private", "--hostname", name,
        "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONUNBUFFERED=1",
    ]
    if secret:
        if role == "adapter":
            raise ValueError("Adapter must not receive harness secret")
        args += ["--secret", f"{secret},type=mount,target=harness,uid=10001,gid=10001,mode=0400"]
    return args


def topology() -> dict:
    return {
        "networks": NETWORKS, "addresses": ADDRESSES,
        "edges": [asdict(edge) for edge in EDGES],
        "policies": {role: nft_policy(role) for role in ROLES},
    }


def runtime_hardened(status: dict) -> bool:
    return status == {
        "uid": 10001, "gid": 10001, "cap_eff": "0000000000000000",
        "no_new_privileges": 1, "seccomp": 2,
    }


def all_capabilities_dropped(values: list[str]) -> bool:
    normalized = {value.upper() for value in values}
    return "ALL" in normalized or DEFAULT_CAPABILITIES.issubset(normalized)


def proof_complete(probes: list[dict], checks: dict) -> bool:
    required = {
        "gateway_http", "gateway_mcp", "deny_direct_services", "deny_capture",
        "deny_management", "deny_same_peer_control", "deny_host", "deny_egress",
        "deny_ipv6", "deny_dns", "deny_harness_secret", "deny_control_over_data",
    }
    return (
        len(probes) == len(required)
        and {probe.get("name") for probe in probes} == required
        and all(probe.get("passed") is True for probe in probes)
        and set(checks) == {"platform", "config", "policy_readback", "default_routes", "source"}
        and all(value is True for value in checks.values())
    )


def stable_nft(value: dict) -> str:
    """Remove only kernel-assigned handles/metainfo and mutable packet counters."""
    def clean(item):
        if isinstance(item, dict):
            return {
                key: clean(val) for key, val in item.items()
                if key not in {"handle", "packets", "bytes", "metainfo"}
            }
        if isinstance(item, list):
            return [clean(val) for val in item if not (isinstance(val, dict) and "metainfo" in val)]
        return item
    return json.dumps(clean(value), sort_keys=True)
