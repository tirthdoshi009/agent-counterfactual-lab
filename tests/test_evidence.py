import copy
from html import escape
import json
from pathlib import Path

import pytest

from lab.contracts import ROOT, Scenario, digest, load_json
from lab.evaluator import evaluate, summarize
from lab.report import normalized, write_reports

FIXTURE = load_json(ROOT / "fixtures" / "workspace.json")
CASES = {
    row["id"]: Scenario.model_validate(row)
    for row in load_json(ROOT / "cases" / "scenarios.json")["cases"]
}


def sample() -> dict:
    case = CASES["control-tenant"]
    run_id = "test-run"
    action = case.actions[0].model_dump()
    reply = {
        "run_id": run_id, "call_id": f"{run_id}:0", "decision": "allow",
        "reason": "authorized", "data": {
            "tenant": "aster", "record": FIXTURE["records"]["aster"]
        },
    }
    service = {
        **reply, "layer": "service", "action": action, "checks_enabled": True,
        "principal": FIXTURE["principals"][case.principal],
    }
    gateway = {**service, "layer": "gateway", "service_reply": reply}
    evidence = {
        "case_id": case.id, "variant": "guarded", "transport": "http", "adversarial": False,
        "run_id": run_id, "reset_verified": True, "errors": [],
        "proposal_hash": digest([action]), "snapshots": {},
        "transcript": [{
            "call": {"run_id": run_id, "call_id": f"{run_id}:0", "action": action}, "reply": reply
        }],
    }
    for name, audit in (("gateway", [gateway]), ("services", [service]), ("capture", [])):
        evidence["snapshots"][name] = {
            "run_id": run_id, "fixture_hash": digest(FIXTURE),
            "workspace": copy.deepcopy(FIXTURE), "audit": audit, "capture": [],
        }
    return json.loads(json.dumps(evidence))


def test_complete_consistent_evidence_passes():
    result = evaluate(CASES["control-tenant"], sample(), FIXTURE)
    assert result["status"] == "completed"
    assert result["benign_success"] is True


@pytest.mark.parametrize("fault", [
    "missing_service", "conflicting_reply", "unrelated_mutation", "unexpected_capture",
    "bad_reset", "timeout", "missing_snapshot", "wrong_identity", "wrong_run", "wrong_proposal",
])
def test_missing_conflicting_or_error_evidence_is_inconclusive(fault):
    evidence = sample()
    match fault:
        case "missing_service":
            evidence["snapshots"]["services"]["audit"].clear()
        case "conflicting_reply":
            evidence["transcript"][0]["reply"]["data"]["record"] = "FORGED"
        case "unrelated_mutation":
            evidence["snapshots"]["services"]["workspace"]["records"]["birch"] = "TAMPERED"
        case "unexpected_capture":
            evidence["snapshots"]["capture"]["capture"].append({"payload": "TAMPERED"})
        case "bad_reset":
            evidence["reset_verified"] = False
        case "timeout":
            evidence["errors"].append("TimeoutError")
        case "missing_snapshot":
            evidence["snapshots"].pop("gateway")
        case "wrong_identity":
            evidence["snapshots"]["gateway"]["audit"][0]["principal"]["role"] = "admin"
        case "wrong_run":
            evidence["snapshots"]["services"]["run_id"] = "foreign-run"
        case "wrong_proposal":
            evidence["proposal_hash"] = "mismatch"
    result = evaluate(CASES["control-tenant"], evidence, FIXTURE)
    assert result["status"] == "inconclusive"
    assert result["benign_success"] is None
    assert result["errors"]


def test_no_attempt_is_not_a_blocked_success():
    evidence = sample()
    evidence["transcript"] = []
    evidence["errors"] = ["adapter_timeout"]
    result = evaluate(CASES["control-tenant"], evidence, FIXTURE)
    assert result["status"] == "inconclusive"
    assert result["attempt"] == "no_attempt"


def test_inconclusive_excluded_from_denominator():
    valid = {
        "variant": "guarded", "transport": "http", "adversarial": True,
        "evaluation": {
            "status": "completed", "attack_success": False, "benign_success": None,
            "attempt": "attempted_but_blocked", "errors": [],
        },
    }
    invalid = copy.deepcopy(valid)
    invalid["evaluation"].update({
        "status": "inconclusive", "attack_success": None, "attempt": "no_attempt",
        "errors": ["timeout"],
    })
    row = summarize([valid, invalid])[0]
    assert row["valid_adversarial"] == 1
    assert row["attack_success_rate"] == 0
    assert row["inconclusive"] == 1
    assert row["no_attempt"] == 1
    assert row["attempted_but_blocked"] == 1


def test_html_escapes_untrusted_evidence(tmp_path: Path):
    evidence = sample()
    evidence["evaluation"] = evaluate(CASES["control-tenant"], evidence, FIXTURE)
    marker = "<script>synthetic()</script>"
    evidence["errors"] = [marker]
    write_reports(tmp_path, {"mode": "local_simulation"}, [evidence])
    html = (tmp_path / "report.html").read_text()
    assert marker not in html
    assert escape(marker) in html
    assert "default-src 'none'" in html
    assert json.loads((tmp_path / "report.json").read_text())["executions"][0]["errors"] == [marker]


def test_normalization_omits_correlation_ids():
    first = sample()
    first["evaluation"] = evaluate(CASES["control-tenant"], first, FIXTURE)
    second = copy.deepcopy(first)
    second["run_id"] = "different-run"
    second["transcript"][0]["call"]["run_id"] = "different-run"
    second["transcript"][0]["reply"]["run_id"] = "different-run"
    assert normalized([first]) == normalized([second])
