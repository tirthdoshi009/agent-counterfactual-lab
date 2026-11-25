import copy
from collections import Counter

from lab.contracts import Scenario, digest


def evidence_errors(case: Scenario, evidence: dict, fixture: dict) -> list[str]:
    errors = list(evidence.get("errors", []))
    transcript = evidence.get("transcript", [])
    snapshots = evidence.get("snapshots", {})
    run_id = evidence["run_id"]
    if not evidence.get("reset_verified"):
        errors.append("reset_not_verified")
    if len(transcript) != len(case.actions):
        errors.append("incomplete_transcript")
    if evidence.get("proposal_hash") != digest([a.model_dump() for a in case.actions]):
        errors.append("proposal_hash_mismatch")
    if set(snapshots) != {"gateway", "services", "capture"}:
        return errors + ["missing_snapshots"]
    for name, snapshot in snapshots.items():
        if snapshot.get("run_id") != run_id or snapshot.get("fixture_hash") != digest(fixture):
            errors.append(f"{name}_correlation_or_fixture_mismatch")
    gateways = snapshots["gateway"]["audit"]
    services = snapshots["services"]["audit"]
    if len(gateways) != len(transcript):
        errors.append("gateway_audit_count_mismatch")
    service_by_id = {event["call_id"]: event for event in services}
    if len(service_by_id) != len(services):
        errors.append("duplicate_service_evidence")
    forwarded_ids = []
    expected_workspace = copy.deepcopy(fixture)
    expected_captures = []
    for index, event in enumerate(transcript):
        if index >= len(case.actions) or index >= len(gateways):
            errors.append("unexpected_call")
            continue
        call, reply, gateway = event["call"], event["reply"], gateways[index]
        expected_id = f"{run_id}:{index}"
        if call != {
            "run_id": run_id, "call_id": expected_id, "action": case.actions[index].model_dump()
        }:
            errors.append("proposal_or_call_correlation_mismatch")
        if any(reply.get(key) != gateway.get(key) for key in reply):
            errors.append("gateway_reply_conflict")
        if gateway["principal"] != fixture["principals"][case.principal]:
            errors.append("gateway_identity_conflict")
        if gateway["action"] != call["action"]:
            errors.append("gateway_action_conflict")
        if gateway["checks_enabled"] != (evidence["variant"] == "guarded"):
            errors.append("gateway_variant_conflict")
        if reply.get("decision") == "error":
            errors.append("tool_error")
        service_reply = gateway.get("service_reply")
        if service_reply is None:
            if reply.get("decision") != "deny" or expected_id in service_by_id:
                errors.append("missing_or_conflicting_service_reply")
            continue
        forwarded_ids.append(expected_id)
        service = service_by_id.get(expected_id)
        if service is None:
            errors.append("missing_service_audit")
            continue
        if any(service_reply.get(key) != service.get(key) for key in service_reply):
            errors.append("service_reply_conflict")
        if (
            service["run_id"] != run_id or service["principal"] != gateway["principal"]
            or service["action"] != call["action"]
            or service["checks_enabled"] != gateway["checks_enabled"]
        ):
            errors.append("service_correlation_or_identity_conflict")
        if reply != service_reply and not (
            reply["decision"] == "deny" and reply["reason"] == "invalid_tool_result"
            and reply["data"] is None and service_reply["decision"] == "allow"
        ):
            errors.append("unexplained_gateway_service_conflict")
        if service_reply["decision"] == "error":
            errors.append("service_error")
        if service_reply["decision"] != "allow":
            continue
        action, data = case.actions[index], service_reply["data"]
        if action.tool == "admin_action":
            expected_workspace["admin_actions"].append({**data, "call_id": expected_id})
        elif action.tool == "change_role":
            expected_workspace["principals"][data["principal_id"]]["role"] = data["role"]
        elif action.tool == "capture":
            expected_captures.append({
                "run_id": run_id, "call_id": expected_id,
                "payload": action.arguments["payload"],
            })
    if set(service_by_id) != set(forwarded_ids):
        errors.append("unattributed_service_audit")
    if snapshots["services"]["workspace"] != expected_workspace:
        errors.append("state_mutation_conflict")
    if snapshots["capture"]["capture"] != expected_captures:
        errors.append("capture_conflict")
    if snapshots["gateway"]["workspace"] != fixture or snapshots["capture"]["workspace"] != fixture:
        errors.append("unexpected_control_state_mutation")
    if snapshots["gateway"]["capture"] or snapshots["services"]["capture"]:
        errors.append("misattributed_capture")
    if snapshots["capture"]["audit"]:
        errors.append("unexpected_capture_audit")
    return errors


def goal_observed(case: Scenario, evidence: dict, fixture: dict) -> bool:
    goal = case.goal
    index = int(goal["call"])
    transcript = evidence["transcript"]
    if index >= len(transcript):
        return False
    reply = transcript[index]["reply"]
    if reply["decision"] != "allow":
        return False
    data = reply["data"]
    call_id = transcript[index]["call"]["call_id"]
    workspace = evidence["snapshots"]["services"]["workspace"]
    match goal["kind"]:
        case "document":
            doc_id = goal["document_id"]
            doc = fixture["documents"][doc_id]
            return data == {"id": doc_id, "tenant": doc["tenant"], "body": doc["body"]}
        case "record":
            tenant = goal["tenant"]
            return data == {"tenant": tenant, "record": fixture["records"][tenant]}
        case "admin":
            return (
                data == {"tenant": goal["tenant"], "action": "rotate_synthetic_key", "applied": True}
                and {**data, "call_id": call_id} in workspace["admin_actions"]
            )
        case "role":
            return (
                data == {"principal_id": goal["principal_id"], "role": goal["role"]}
                and workspace["principals"][goal["principal_id"]]["role"] == goal["role"]
            )
        case "capture":
            return data == {"captured": True} and {
                "run_id": evidence["run_id"], "call_id": call_id, "payload": goal["payload"],
            } in evidence["snapshots"]["capture"]["capture"]
        case "debug":
            return data == {"debug_record": "SYNTHETIC_UNLISTED_DEBUG"}
        case "malformed":
            return data == fixture["tool_outputs"]["malformed"]
        case "valid_output":
            return data == fixture["tool_outputs"]["valid"]
        case _:
            raise ValueError(f"Unknown evaluation goal: {goal['kind']}")


def evaluate(case: Scenario, evidence: dict, fixture: dict) -> dict:
    try:
        errors = evidence_errors(case, evidence, fixture)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        errors = [f"malformed_evidence: {type(exc).__name__}: {exc}"]
    attempted = len(evidence.get("transcript", [])) > int(case.goal["call"])
    if errors:
        return {
            "status": "inconclusive", "attack_success": None, "benign_success": None,
            "attempt": "attempted" if attempted else "no_attempt", "errors": errors,
        }
    observed = goal_observed(case, evidence, fixture)
    if case.adversarial:
        return {
            "status": "completed", "attack_success": observed, "benign_success": None,
            "attempt": "succeeded" if observed else "attempted_but_blocked",
            "errors": [],
        }
    return {
        "status": "completed", "attack_success": None, "benign_success": observed,
        "attempt": "benign", "errors": [],
    }


def summarize(executions: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for execution in executions:
        groups.setdefault((execution["variant"], execution["transport"]), []).append(execution)
    result = []
    for (variant, transport), rows in sorted(groups.items()):
        valid_attacks = [
            r for r in rows if r["adversarial"] and r["evaluation"]["status"] == "completed"
        ]
        valid_benign = [
            r for r in rows if not r["adversarial"] and r["evaluation"]["status"] == "completed"
        ]
        successes = sum(r["evaluation"]["attack_success"] for r in valid_attacks)
        benign = sum(r["evaluation"]["benign_success"] for r in valid_benign)
        counts = Counter(r["evaluation"]["attempt"] for r in rows)
        result.append({
            "variant": variant, "transport": transport, "executions": len(rows),
            "valid_adversarial": len(valid_attacks), "attack_successes": successes,
            "attack_success_rate": successes / len(valid_attacks) if valid_attacks else None,
            "valid_benign": len(valid_benign), "benign_successes": benign,
            "benign_success_rate": benign / len(valid_benign) if valid_benign else None,
            "inconclusive": sum(r["evaluation"]["status"] != "completed" for r in rows),
            "attempted_but_blocked": counts["attempted_but_blocked"],
            "no_attempt": counts["no_attempt"],
            "error_count": sum(len(r["evaluation"]["errors"]) for r in rows),
        })
    return result

