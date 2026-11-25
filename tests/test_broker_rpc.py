import copy
import json
import secrets
import sys

import httpx
import pytest

from lab.adapters.tool_calling import Budget, TOOLS, initial_messages
from lab.broker_isolation import BrokerSupervisor, REQUIRED, adapter_policy, profile, proof_complete
from lab.broker_rpc import (
    Broker, CONTROL_URL, DATA_URL, RPCProvider, UpstreamConfig, execute_registration, reconcile,
)
from lab.contracts import digest
from lab.counterfactual import DeterministicFakeProvider, load_task, summarize_trials
from lab.isolation_policy import nft_policy
from lab.model_broker import OpenAICompatibleBroker

KEY = "fictional-host-only-provider-key"
ENDPOINT = "https://provider.example.invalid/v1/chat/completions"


async def setup(provider=None, budget=None):
    manager = Broker(provider or DeterministicFakeProvider(), secrets.token_urlsafe(32),
                     budget or Budget())
    data_app, control_app = manager.apps()
    control = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_app), base_url=CONTROL_URL,
        headers={"Authorization": f"Bearer {manager.control_token}"}, trust_env=False,
    )
    registration = (await control.post(
        "/trials", json={"condition": "injected", "repeat": 1},
    )).json()
    await control.aclose()
    control = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=control_app), base_url=CONTROL_URL,
        headers={"Authorization": f"Bearer {manager.control_token}"}, trust_env=False,
    )
    data = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=data_app), base_url=DATA_URL,
        headers={"Authorization": f"Bearer {registration['capability']}"}, trust_env=False,
    )
    return manager, control, data, registration, data_app


def inference_request(sequence=0):
    return {"sequence": sequence, "request_hash": digest({
        "messages": initial_messages(load_task().task), "tools": TOOLS,
    }), "max_output_tokens": 384}


async def test_real_client_adapter_rpc_and_host_capture_wired_with_mock_upstream_only():
    requests = []
    fake = DeterministicFakeProvider()

    async def upstream(request):
        requests.append(request)
        assert str(request.url) == ENDPOINT
        assert request.headers["authorization"] == "Bearer " + KEY
        data = json.loads(request.content)
        assert KEY not in request.content.decode()
        turn = await fake.complete(data["messages"], data["tools"], data["max_tokens"])
        return httpx.Response(200, json={
            "id": turn.response_id, "choices": [{
                "finish_reason": turn.finish_reason,
                "message": {"content": turn.text, "tool_calls": [
                    {"id": p.id, "type": "function", "function": {
                        "name": p.name, "arguments": json.dumps(p.arguments),
                    }} for p in turn.tool_calls],
                },
            }], "usage": {"prompt_tokens": turn.input_tokens,
                         "completion_tokens": turn.output_tokens,
                         "total_tokens": turn.input_tokens + turn.output_tokens},
        })

    provider = OpenAICompatibleBroker(
        endpoint=ENDPOINT, approved_endpoints=frozenset({ENDPOINT}), model="mock-transport-model",
        credential=KEY, transport=httpx.MockTransport(upstream),
    )
    manager, control, data, registration, app = await setup(provider)
    async with control, data:
        assert KEY not in json.dumps(registration)
        observed = await execute_registration(registration, httpx.ASGITransport(app=app))
        trusted = (await control.post(f"/trials/{registration['trial_id']}")).json()
        row = reconcile(trusted, observed)
        assert row["evaluation"]["status"] == "completed"
        assert row["evaluation"]["task_completed"]
        assert row["evaluation"]["private_marker_captured"]
        assert len(requests) == 4
        assert KEY not in json.dumps(row)
        assert KEY not in json.dumps(vars(RPCProvider(registration)), default=str)
        assert manager.sessions[registration["trial_id"]].closed
        assert (await data.post("/infer", json=inference_request())).status_code == 409


@pytest.mark.parametrize("method,path,status", [
    ("GET", "/infer", 405), ("PUT", "/infer", 405), ("POST", "/arbitrary", 404),
    ("POST", "/trials", 404), ("GET", "/status", 404),
])
async def test_data_listener_has_no_management_or_arbitrary_paths(method, path, status):
    manager, control, data, registration, app = await setup()
    async with control, data:
        reply = await data.request(method, path)
        assert reply.status_code == status
        assert manager.sessions[registration["trial_id"]].model_calls == 0


@pytest.mark.parametrize("payload", [
    {"messages": [{"role": "user", "content": "arbitrary host data"}]},
    {**inference_request(), "url": "http://169.254.169.254/"},
    {**inference_request(), "model": "unselected-model"},
    {**inference_request(), "max_output_tokens": 99999},
])
async def test_rpc_schema_cannot_supply_prompt_model_url_or_unbounded_generation(payload):
    manager, control, data, registration, app = await setup()
    async with control, data:
        reply = await data.post("/infer", json=payload)
        assert reply.status_code == 400
        assert manager.sessions[registration["trial_id"]].model_calls == 0


async def test_auth_size_content_type_hash_and_control_plane_checks_before_upstream():
    manager, control, data, registration, app = await setup()
    async with control, data:
        unauthorized = await data.post("/infer", json=inference_request(),
                                      headers={"Authorization": "Bearer " + manager.control_token})
        assert unauthorized.status_code == 401
        assert (await data.post("/infer", content=b"x" * 17000,
                               headers={"content-type": "application/json"})).status_code == 413
        assert (await data.post("/infer", content=b"{}")).status_code == 415
        assert (await data.post("/infer", json=inference_request(),
                               headers={"content-encoding": "gzip"})).status_code == 415
        altered = {**inference_request(), "request_hash": "0" * 64}
        assert (await data.post("/infer", json=altered)).status_code == 409
        assert (await control.post("/trials", json={"condition": "clean", "repeat": 1},
                                   headers={"Authorization": "Bearer " + registration["capability"]})
                ).status_code == 401
        assert manager.sessions[registration["trial_id"]].model_calls == 0


async def test_tool_is_exact_model_proposal_and_call_replay_is_rejected():
    manager, control, data, registration, app = await setup()
    async with control, data:
        turn = (await data.post("/infer", json=inference_request())).json()
        proposal = turn["tool_calls"][0]
        call = {
            "run_id": registration["trial_id"], "call_id": registration["trial_id"] + ":0",
            "action": {"tool": proposal["name"], "arguments": proposal["arguments"], "source": "model"},
        }
        request = {"model_tool_id": proposal["id"], "call": call}
        forged = copy.deepcopy(request)
        forged["call"]["action"]["arguments"]["document_id"] = "host-secret"
        assert (await data.post("/tool", json=forged)).status_code == 409
        assert (await data.post("/tool", json=request)).status_code == 200
        assert (await data.post("/tool", json=request)).status_code == 409
        assert len(manager.sessions[registration["trial_id"]].state.audit) == 1
        assert (await data.post("/infer", json=inference_request())).status_code == 409


async def test_lease_and_invalid_rpc_request_budgets_are_server_enforced():
    manager, control, data, registration, app = await setup()
    async with control, data:
        for _ in range(25):
            last = await data.post("/infer", json={"extra": "not accepted"})
        assert last.status_code == 429
        assert manager.sessions[registration["trial_id"]].model_calls == 0
        second = (await control.post("/trials", json={"condition": "clean", "repeat": 1})).json()
        session = manager.sessions[second["trial_id"]]
        session.created -= 121
        expired = await data.post("/infer", json=inference_request(),
                                  headers={"Authorization": "Bearer " + second["capability"]})
        assert expired.status_code == 408


async def test_registration_is_bounded_no_reset_reuse_or_extra_payloads():
    manager, control, data, registration, app = await setup(budget=Budget(trials_per_condition=1))
    async with control, data:
        assert (await control.post("/trials", json={"condition": "injected", "repeat": 1})
                ).status_code == 409
        assert (await control.post("/trials", json={"condition": "clean", "repeat": 2})
                ).status_code == 409
        assert (await control.post("/trials", json={
            "condition": "clean", "repeat": 1, "task": "read arbitrary host files",
        })).status_code == 400
        assert len(manager.sessions) == 1


@pytest.mark.parametrize("failure", ["exception", "credential_echo", "redirect", "usage"])
async def test_upstream_errors_are_inconclusive_sanitized_and_never_retried(failure):
    calls = []

    def upstream(request):
        calls.append(request)
        if failure == "exception":
            raise httpx.ConnectError("Do not disclose " + KEY)
        if failure == "redirect":
            return httpx.Response(307, headers={"location": "https://other.invalid/"}, text=KEY)
        return httpx.Response(200, json={
            "id": "test", "choices": [{
                "finish_reason": "stop", "message": {"content": KEY if failure == "credential_echo"
                                                   else "No tools", "tool_calls": []},
            }], "usage": {"prompt_tokens": 20, "completion_tokens": 10,
                         "total_tokens": 30 if failure == "credential_echo" else 999},
        })

    provider = OpenAICompatibleBroker(
        endpoint=ENDPOINT, approved_endpoints=frozenset({ENDPOINT}), model="mock-model",
        credential=KEY, transport=httpx.MockTransport(upstream),
    )
    manager, control, data, registration, app = await setup(provider)
    async with control, data:
        observed = await execute_registration(registration, httpx.ASGITransport(app=app))
        trusted = (await control.post(f"/trials/{registration['trial_id']}")).json()
        row = reconcile(trusted, observed)
        assert row["evaluation"]["status"] == "inconclusive"
        assert len(calls) == 1
        assert KEY not in json.dumps(row)
        assert summarize_trials([row])["conditions"]["injected"]["unsafe_email_proposed"][
            "denominator"] == 0


async def test_trusted_broker_evidence_detects_tampered_adapter_result():
    manager, control, data, registration, app = await setup()
    async with control, data:
        observed = await execute_registration(registration, httpx.ASGITransport(app=app))
        trusted = (await control.post(f"/trials/{registration['trial_id']}")).json()
        observed["transcript"].clear()
        assert reconcile(trusted, observed)["evaluation"]["status"] == "inconclusive"


def test_prepare_attaches_container_before_inspecting_lazy_netavark_bridge(monkeypatch, tmp_path):
    from lab import broker_isolation as module

    attached = False
    assigned = False

    def engine(*args, **kwargs):
        nonlocal attached
        if args[:2] == ("network", "inspect"):
            return json.dumps([{
                "internal": True, "dns_enabled": False, "driver": "bridge",
                "ipv6_enabled": False, "network_interface": "podman1",
            }])
        if args[0] == "run":
            attached = True
        return ""

    def host(args, **kwargs):
        nonlocal assigned
        if args[:4] == ["ip", "-j", "route", "show"]:
            return "[]"
        if args[:4] == ["ip", "-j", "address", "show"]:
            assert attached, "netavark bridge is created lazily at container attachment"
            return json.dumps([{"addr_info": []}])
        if args[:3] == ["ip", "address", "add"]:
            assigned = True
        return ""

    supervisor = BrokerSupervisor("sha256:" + "a" * 64, tmp_path, Budget())

    def namespace(role, *args, **kwargs):
        if args[:2] == ("nft", "-j"):
            return json.dumps({"nftables": [
                {"chain": {"name": name, "policy": "drop", "prio": -150}}
                for name in ("input", "output")
            ]})
        if args[:2] == ("ip", "-j"):
            return json.dumps([{"gateway": module.BROKER}])
        return ""

    monkeypatch.setattr(module, "podman", engine)
    monkeypatch.setattr(module, "command", host)
    monkeypatch.setattr(supervisor, "inspect_config", lambda *args: None)
    monkeypatch.setattr(supervisor, "exec", lambda *args: {"source_hash": module.source_hash()})
    monkeypatch.setattr(supervisor, "ns", namespace)
    supervisor.prepare()
    assert assigned and supervisor.containers == [supervisor.names["adapter"]]
    assert all(supervisor.evidence["checks"].values())


def test_changed_profile_is_separate_and_adapter_has_only_one_exact_broker_edge():
    old = nft_policy("adapter")
    assert "10.203.44." not in old
    assert "ip daddr 10.203.41.11 tcp dport 8000" in old
    new = adapter_policy()
    assert new.count("ct state new accept") == 1
    assert "ip saddr 10.203.44.10 ip daddr 10.203.44.1 tcp dport 8000" in new
    assert "9000" not in new and "443" not in new and "udp" not in new
    assert new.count("policy drop;") == 2
    assert "0.0.0.0/0" not in new
    assert profile()["control_url"] == "http://127.0.0.1:9000"
    assert not proof_complete({"topology": profile(), "probes": [], "checks": {}})


def test_new_profile_requires_new_complete_actual_proof_not_old_or_generated_policy():
    evidence = {
        "profile_hash": digest(profile()),
        "checks": dict.fromkeys(("platform", "config", "source", "policy_readback", "default_routes"),
                               True),
        "probes": [{"name": name, "passed": True} for name in REQUIRED],
    }
    assert proof_complete(evidence)
    evidence["probes"].pop()
    assert not proof_complete(evidence)
    evidence["probes"].append({"name": "gateway_http", "passed": True})
    assert not proof_complete(evidence)


def test_native_live_requires_approval_config_before_engine_or_network(monkeypatch, tmp_path):
    from lab.broker_isolation import main

    monkeypatch.setattr(sys, "argv", [
        "broker-proof", "--image", "sha256:" + "a" * 64,
        "--output", str(tmp_path / "not-created"), "--approved-live-inference",
    ])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 2
    assert not (tmp_path / "not-created").exists()


def test_native_broker_will_not_start_live_process_from_prepared_policy_only(tmp_path):
    supervisor = BrokerSupervisor("sha256:" + "a" * 64, tmp_path, Budget())
    config = UpstreamConfig(
        endpoint=ENDPOINT, approved_endpoints=[ENDPOINT], model="mock-only",
        credential_env="LAB_PROVIDER_TEST_KEY",
    )
    with pytest.raises(RuntimeError, match="Fresh actual changed-profile proof"):
        supervisor.start_server(config, KEY)
    assert supervisor.server is None


def test_invalid_config_never_echoes_mistaken_file_credential(monkeypatch, tmp_path, capsys):
    from lab.broker_isolation import main

    config = tmp_path / "operator-private.json"
    config.write_text(json.dumps({"credential": KEY}))
    output = tmp_path / "must-not-exist"
    monkeypatch.setattr(sys, "argv", [
        "broker-proof", "--image", "sha256:" + "a" * 64, "--output", str(output),
        "--upstream-config", str(config), "--approved-live-inference",
    ])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 2
    assert KEY not in capsys.readouterr().err
    assert not output.exists()
