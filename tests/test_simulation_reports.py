from lab.contracts import digest
from lab.report import normalized
from tests.test_evidence import CASES, FIXTURE


def test_actual_matrices_have_complete_consistent_evidence(simulation_reports):
    from lab.evaluator import evaluate

    summary, reports = simulation_reports
    assert summary["executions"] == 120
    assert summary["repeats"] == 2
    run_ids = set()
    for report in reports:
        assert len(report["executions"]) == 60
        for execution in report["executions"]:
            assert execution["run_id"] not in run_ids
            run_ids.add(execution["run_id"])
            assert execution["reset_verified"]
            result = evaluate(CASES[execution["case_id"]], execution, FIXTURE)
            assert result == execution["evaluation"]
            assert result["status"] == "completed"
            assert result["errors"] == []
            if execution["adversarial"]:
                assert result["attack_success"] == (execution["variant"] == "vulnerable")
            else:
                assert result["benign_success"] is True


def test_actual_repeats_normalize_identically(simulation_reports):
    summary, reports = simulation_reports
    assert summary["repeatable"]
    hashes = [digest(normalized(report["executions"])) for report in reports]
    assert hashes == summary["normalized_hashes"]
    assert len(set(hashes)) == 1
    by_case = {}
    for execution in reports[0]["executions"]:
        by_case.setdefault(execution["case_id"], set()).add(execution["proposal_hash"])
    assert all(len(hashes) == 1 for hashes in by_case.values())


def test_actual_injection_uses_foreign_data_evidence(simulation_reports):
    _, reports = simulation_reports
    for execution in reports[0]["executions"]:
        if execution["case_id"] != "pi-foreign":
            continue
        initial, followup = execution["transcript"]
        assert initial["reply"]["data"]["body"] == FIXTURE["documents"]["aster-inject-foreign"]["body"]
        if execution["variant"] == "vulnerable":
            assert followup["reply"]["data"] == {
                "tenant": "birch", "record": FIXTURE["records"]["birch"]
            }
        else:
            assert followup["reply"]["decision"] == "deny"
            assert followup["reply"]["data"] is None
            assert len(execution["snapshots"]["services"]["audit"]) == 1


def test_actual_capture_exists_only_for_seeded_vulnerable_exfiltration(simulation_reports):
    _, reports = simulation_reports
    for report in reports:
        for execution in report["executions"]:
            records = execution["snapshots"]["capture"]["capture"]
            expected = execution["case_id"] == "output-exfil" and execution["variant"] == "vulnerable"
            assert bool(records) == expected
            if records:
                assert len(records) == 1
                assert records[0]["payload"] == "SYNTHETIC_EXFIL_MARKER"
                assert records[0]["run_id"] == execution["run_id"]


def test_actual_forged_fields_do_not_change_resolved_identity(simulation_reports):
    _, reports = simulation_reports
    for execution in reports[0]["executions"]:
        if execution["case_id"] != "privilege-forged":
            continue
        gateway = execution["snapshots"]["gateway"]["audit"][0]
        assert gateway["action"]["arguments"]["role"] == "admin"
        assert gateway["principal"] == FIXTURE["principals"]["aster-reader"]
        if execution["variant"] == "guarded":
            assert gateway["reason"] == "admin_required"
            assert not execution["state_delta"]


def test_actual_reports_disclaim_isolation_and_helpers_are_stopped(simulation_reports):
    summary, reports = simulation_reports
    assert summary["task_owned_processes_stopped"]
    for report in reports:
        isolation = report["manifest"]["isolation"]
        assert isolation["mode"] == "local_simulation"
        assert isolation["binding"] == "127.0.0.1"
        assert not isolation["container_validated"]
        assert not isolation["host_network_isolation_verified"]


def test_actual_mcp_run_has_no_teardown_or_settings_diagnostics(simulation_reports):
    summary, reports = simulation_reports
    diagnostics = summary["runtime_diagnostics"]
    assert diagnostics["router_cleanup_errors"] == 0
    assert diagnostics["settings_warning"] is None
    assert diagnostics["other_logged_errors"] == []
    for report in reports:
        assert report["manifest"]["runtime_diagnostics"] == diagnostics
