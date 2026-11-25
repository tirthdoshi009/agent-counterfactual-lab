import json

from lab.contracts import ROOT, load_json
from lab.isolation_policy import proof_complete, runtime_hardened, stable_nft


def test_actual_linux_proof_is_complete_not_inferred_from_preparation(isolation_evidence):
    _, proof = isolation_evidence
    assert proof["verified"] is True
    assert proof["status"] == "proof_executed"
    assert proof["errors"] == []
    assert proof["cleanup"] is True
    assert proof_complete(proof["probes"], proof["checks"])
    assert proof["preflight"]["platform"] == "Linux"
    assert proof["preflight"]["security"]["rootless"] is False
    assert proof["preflight"]["security"]["seccompEnabled"] is True


def test_actual_denied_connections_have_namespace_rejection_evidence(isolation_evidence):
    _, proof = isolation_evidence
    probes = {row["name"]: row for row in proof["probes"]}
    for name in (
        "deny_direct_services", "deny_capture", "deny_management", "deny_same_peer_control",
        "deny_host", "deny_egress", "deny_ipv6",
    ):
        assert probes[name]["result"]["connected"] is False
        assert probes[name]["counter_after"] > probes[name]["counter_before"]
    assert probes["deny_dns"]["result"]["received"] is False
    assert probes["deny_dns"]["counter_after"] > probes["deny_dns"]["counter_before"]
    assert probes["deny_harness_secret"]["result"] == {"secret_exists": False}
    assert probes["deny_control_over_data"]["result"]["status"] == 404


def test_actual_permitted_http_and_mcp_return_exact_synthetic_data(isolation_evidence):
    _, proof = isolation_evidence
    fixture = load_json(ROOT / "fixtures" / "workspace.json")
    doc = fixture["documents"]["aster-guide"]
    for row in proof["probes"]:
        if row["name"].startswith("gateway_"):
            assert row["reply"]["decision"] == "allow"
            assert row["reply"]["data"] == {
                "id": "aster-guide", "tenant": doc["tenant"], "body": doc["body"],
            }
    for role in ("gateway", "services"):
        audit = proof["audit_evidence"][role]["audit"]
        assert len(audit) == 2
        assert all(row["principal"] == fixture["principals"]["aster-reader"] for row in audit)
        assert all(row["decision"] == "allow" for row in audit)
    for snapshot in proof["audit_evidence"].values():
        assert snapshot["workspace"] == fixture
        assert snapshot["capture"] == []


def test_actual_container_hardening_and_policy_unchanged(isolation_evidence):
    _, proof = isolation_evidence
    for role, row in proof["containers"].items():
        assert runtime_hardened(row["process_hardening"])
        assert row["hardening"]["ReadonlyRootfs"]
        assert row["hardening"]["Privileged"] is False
        assert not row["hardening"]["PortBindings"]
        assert row["hardening"]["Memory"] == 384 * 1024 * 1024
        policy = proof["policies"][role]
        assert stable_nft(policy["installed"]) == stable_nft(policy["after_probes"])
        assert policy["generated"].count("policy drop;") == 2


def test_actual_task_owned_containers_networks_and_secrets_are_removed(isolation_evidence):
    directory, _ = isolation_evidence
    assert json.loads((directory / "abl-containers-after-proof.json").read_text()) == []
    networks = json.loads((directory / "abl-networks-after-proof.json").read_text())
    assert all(not network["name"].startswith("abl-") for network in networks)
    assert (directory / "abl-secrets-after-proof.json").read_text().strip() in {"", "[]"}


def test_failed_native_attempts_preserved_not_mislabeled(isolation_evidence):
    directory, _ = isolation_evidence
    for index in (1, 2, 3):
        failed = json.loads((directory / f"abl-proof-{index}" / "isolation-proof.json").read_text())
        assert failed["verified"] is False
        assert failed["status"] == "blocked_or_failed"
        assert failed["errors"]
