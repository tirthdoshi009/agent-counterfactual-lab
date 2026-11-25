import asyncio
import copy
import secrets
import uuid

import httpx

from lab.contracts import Job, Principal, ROOT, Suite, digest, load_json
from lab.evaluator import evaluate


class Runner:
    def __init__(self, endpoints: dict[str, str], control_token: str) -> None:
        self.endpoints = endpoints
        self.control_token = control_token
        self.fixture = load_json(ROOT / "fixtures" / "workspace.json")
        self.raw_suite = load_json(ROOT / "cases" / "scenarios.json")
        self.suite = Suite.model_validate(self.raw_suite)
        ids = [case.id for case in self.suite.cases]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate scenario identifiers")

    async def control(self, name: str, operation: str, provision: dict | None = None) -> dict:
        async with httpx.AsyncClient(timeout=4, trust_env=False) as client:
            url = f"{self.endpoints[name]}/control/{operation}"
            headers = {"Authorization": f"Bearer {self.control_token}"}
            if provision is not None:
                response = await client.post(url, json=provision, headers=headers)
            else:
                response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

    async def run(self, variants: list[str], transports: list[str]) -> list[dict]:
        executions = []
        for case in self.suite.cases:
            for variant in variants:
                for transport in transports:
                    run_id = str(uuid.uuid4())
                    tokens = {key: secrets.token_urlsafe(32) for key in self.fixture["principals"]}
                    provision = {
                        "run_id": run_id, "variant": variant,
                        "fixture_hash": digest(self.fixture), "max_calls": self.suite.max_calls,
                        "identities": {
                            tokens[key]: Principal.model_validate(principal).model_dump()
                            for key, principal in self.fixture["principals"].items()
                        },
                    }
                    evidence = {
                        "case_id": case.id, "category": case.category, "adversarial": case.adversarial,
                        "principal": case.principal, "run_id": run_id,
                        "variant": variant, "transport": transport,
                        "reset_verified": False, "errors": [], "transcript": [], "snapshots": {},
                        "proposal_hash": None, "state_delta": {},
                    }
                    try:
                        for name in ("capture", "services", "gateway"):
                            reset = await self.control(name, "reset", provision)
                            expected = {
                                "run_id": run_id, "fixture_hash": digest(self.fixture),
                                "workspace": self.fixture, "audit": [], "capture": [],
                            }
                            if reset != expected or await self.control(name, "snapshot") != expected:
                                raise ValueError(f"{name}: reset verification failed")
                        evidence["reset_verified"] = True
                        job = Job(
                            run_id=run_id, token=tokens[case.principal], transport=transport,
                            actions=case.actions, max_calls=self.suite.max_calls,
                            call_timeout_seconds=self.suite.call_timeout_seconds,
                            case_timeout_seconds=self.suite.case_timeout_seconds,
                        )
                        async with asyncio.timeout(self.suite.case_timeout_seconds + 2):
                            async with httpx.AsyncClient(
                                timeout=self.suite.case_timeout_seconds + 1, trust_env=False,
                            ) as client:
                                response = await client.post(
                                    f"{self.endpoints['adapter']}/execute", json=job.model_dump()
                                )
                                response.raise_for_status()
                                body = response.json()
                        evidence["transcript"] = body["transcript"]
                        evidence["proposal_hash"] = body["proposal_hash"]
                        evidence["errors"].extend(body["errors"])
                    except (httpx.HTTPError, TimeoutError, KeyError, ValueError) as exc:
                        evidence["errors"].append(f"runner_error: {type(exc).__name__}: {exc}")
                    # Snapshots are collected even after a partial adapter failure.
                    for name in ("gateway", "services", "capture"):
                        try:
                            evidence["snapshots"][name] = copy.deepcopy(
                                await self.control(name, "snapshot")
                            )
                        except (httpx.HTTPError, ValueError) as exc:
                            evidence["errors"].append(f"snapshot_error: {name}: {exc}")
                    service_state = evidence["snapshots"].get("services", {}).get("workspace", {})
                    evidence["state_delta"] = {
                        key: {"before": self.fixture[key], "after": value}
                        for key, value in service_state.items() if self.fixture.get(key) != value
                    }
                    evidence["evaluation"] = evaluate(case, evidence, self.fixture)
                    executions.append(evidence)
        return executions
