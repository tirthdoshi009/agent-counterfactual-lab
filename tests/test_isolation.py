import copy
import json

import pytest

from lab.isolation import IsolationError, Supervisor, immutable_image_id, preflight, validate_platform
from lab.isolation_policy import (
    ADDRESSES, DEFAULT_CAPABILITIES, EDGES, ROLES, all_capabilities_dropped, container_options,
    nft_policy, proof_complete, runtime_hardened, stable_nft,
)


def supported_info():
    return {
        "version": {"Version": "5.8.10"},
        "host": {
            "os": "linux", "cgroupVersion": "v2", "networkBackend": "netavark",
            "security": {"rootless": False, "seccompEnabled": True},
        },
    }


def test_podman_bare_and_docker_prefixed_image_ids_are_same_immutable_identity():
    image = "a" * 64
    assert immutable_image_id(image) == f"sha256:{image}"
    assert immutable_image_id(f"sha256:{image}") == f"sha256:{image}"
    with pytest.raises(IsolationError):
        immutable_image_id("mutable-tag")


@pytest.mark.parametrize("role", ROLES)
def test_policy_has_exact_declared_new_connection_allowlist(role):
    text = nft_policy(role)
    assert text.count("policy drop;") == 2
    assert "priority -150" in text
    assert "counter name denied_output reject with icmpx type admin-prohibited" in text
    expected = []
    for edge in EDGES:
        if edge.source == role:
            expected.append(
                f"ip saddr {ADDRESSES[role][edge.network]} "
                f"ip daddr {ADDRESSES[edge.destination][edge.network]} "
                f"tcp dport {edge.port} ct state new accept"
            )
        if edge.destination == role:
            expected.append(
                f"ip saddr {ADDRESSES[edge.source][edge.network]} "
                f"ip daddr {ADDRESSES[role][edge.network]} "
                f"tcp dport {edge.port} ct state new accept"
            )
    actual = [line.strip() for line in text.splitlines() if "ct state new accept" in line]
    assert sorted(actual) == sorted(expected)
    assert "udp" not in text
    assert "0.0.0.0/0" not in text


def test_adapter_can_initiate_only_gateway_data_connection():
    output = nft_policy("adapter").split("chain output")[1]
    assert output.count("ct state new accept") == 1
    assert "ip daddr 10.203.41.11 tcp dport 8000" in output
    assert "9000" not in output
    assert "10.203.42.11" not in output


@pytest.mark.parametrize("role", ROLES)
def test_hardened_options_no_privilege_ports_or_shared_host_namespace(role):
    options = container_options(role, "sha256:" + "a" * 64, "abl-012345abcdef-" + role)
    for value in (
        "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=96", "--memory=384m", "--cpus=1", "--pid=private", "--ipc=private",
    ):
        assert value in options
    assert options[options.index("--user") + 1] == "10001:10001"
    assert not any(value.startswith(("--privileged", "--publish", "--volume")) for value in options)


def test_adapter_cannot_receive_control_secret():
    with pytest.raises(ValueError, match="Adapter"):
        container_options("adapter", "sha256:" + "a" * 64, "abl-012345abcdef-adapter", "secret")


def test_podman_expands_cap_drop_all_but_partial_drop_is_rejected():
    assert all_capabilities_dropped(["ALL"])
    assert all_capabilities_dropped(list(DEFAULT_CAPABILITIES))
    assert not all_capabilities_dropped(["CAP_CHOWN"])


@pytest.mark.parametrize("system,uid", [("Windows", 0), ("Linux", 1000), ("Darwin", 0)])
def test_unknown_host_or_nonroot_fails_closed(system, uid):
    with pytest.raises(IsolationError):
        validate_platform(system, uid, dict.fromkeys(("podman", "nsenter", "nft", "ip"), "path"),
                          supported_info())


@pytest.mark.parametrize("failure", ["rootless", "seccomp", "cgroup", "backend", "version", "tool"])
def test_missing_runtime_capabilities_fail_closed(failure):
    info = supported_info()
    tools = dict.fromkeys(("podman", "nsenter", "nft", "ip"), "path")
    match failure:
        case "rootless":
            info["host"]["security"]["rootless"] = True
        case "seccomp":
            info["host"]["security"]["seccompEnabled"] = False
        case "cgroup":
            info["host"]["cgroupVersion"] = "v1"
        case "backend":
            info["host"]["networkBackend"] = "cni"
        case "version":
            info["version"]["Version"] = "6.0.0"
        case "tool":
            tools["nft"] = None
    with pytest.raises(IsolationError):
        validate_platform("Linux", 0, tools, info)


def test_supported_profile_accepted_only_as_prerequisite():
    validate_platform("Linux", 0, dict.fromkeys(("podman", "nsenter", "nft", "ip"), "path"),
                      supported_info())
    assert not proof_complete([], {})


@pytest.mark.parametrize("field,value", [
    ("uid", 0), ("gid", 0), ("cap_eff", "0000000000000001"),
    ("no_new_privileges", 0), ("seccomp", 0),
])
def test_process_hardening_rejects_elevated_or_unfiltered_process(field, value):
    status = {
        "uid": 10001, "gid": 10001, "cap_eff": "0000000000000000",
        "no_new_privileges": 1, "seccomp": 2,
    }
    assert runtime_hardened(status)
    assert not runtime_hardened({**status, field: value})


def test_windows_preflight_never_executes_engine(monkeypatch):
    monkeypatch.setattr("lab.isolation.platform.system", lambda: "Windows")

    def unexpected(*args, **kwargs):
        pytest.fail("Unsupported platform must not invoke engine")

    monkeypatch.setattr("lab.isolation.podman", unexpected)
    with pytest.raises(IsolationError):
        preflight("sha256:" + "a" * 64)


def test_proof_requires_actual_complete_positive_and_negative_probes():
    names = (
        "gateway_http", "gateway_mcp", "deny_direct_services", "deny_capture",
        "deny_management", "deny_same_peer_control", "deny_host", "deny_egress",
        "deny_ipv6", "deny_dns", "deny_harness_secret", "deny_control_over_data",
    )
    probes = [{"name": name, "passed": True} for name in names]
    checks = dict.fromkeys(("platform", "config", "policy_readback", "default_routes", "source"), True)
    assert proof_complete(probes, checks)
    assert not proof_complete(probes[:-1], checks)
    assert not proof_complete(probes + [probes[0]], checks)
    failed = copy.deepcopy(probes)
    failed[0]["passed"] = False
    assert not proof_complete(failed, checks)
    assert not proof_complete(probes, {**checks, "policy_readback": False})


def test_policy_comparison_ignores_counters_not_rules():
    first = {"nftables": [
        {"metainfo": {"release_name": "host-dependent"}},
        {"counter": {"name": "denied_output", "packets": 0, "bytes": 0, "handle": 2}},
        {"rule": {"expr": [{"accept": None}], "handle": 4}},
    ]}
    after = copy.deepcopy(first)
    after["nftables"][1]["counter"].update(packets=2, bytes=40, handle=8)
    assert stable_nft(first) == stable_nft(after)
    after["nftables"][2]["rule"]["expr"] = [{"drop": None}]
    assert stable_nft(first) != stable_nft(after)
    assert json.loads(stable_nft(first))


def test_changed_namespace_policy_blocks_probe_before_container_exec(monkeypatch, tmp_path):
    supervisor = Supervisor("sha256:" + "a" * 64, tmp_path)
    supervisor.policy_baseline["adapter"] = stable_nft({"nftables": [{"rule": {"drop": None}}]})
    monkeypatch.setattr(
        supervisor, "ns", lambda *args: json.dumps({"nftables": [{"rule": {"accept": None}}]}),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Must not execute a probe after policy drift")

    monkeypatch.setattr("lab.isolation.podman", forbidden)
    with pytest.raises(IsolationError, match="changed or restarted"):
        supervisor.exec("adapter", "probe", "connect", "192.0.2.1", "443")
