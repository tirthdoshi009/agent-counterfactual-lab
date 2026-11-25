import copy
import hmac
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lab.contracts import ROOT, Provision, digest, load_json


class State:
    def __init__(self, fixture: dict | None = None) -> None:
        self.fixture = copy.deepcopy(
            fixture if fixture is not None else load_json(ROOT / "fixtures" / "workspace.json")
        )
        self.fixture_hash = digest(self.fixture)
        self.workspace = copy.deepcopy(self.fixture)
        self.provision: Provision | None = None
        self.audit: list[dict] = []
        self.capture: list[dict] = []

    def reset(self, provision: Provision) -> None:
        if provision.fixture_hash != self.fixture_hash:
            raise ValueError("Fixture hash mismatch")
        self.workspace = copy.deepcopy(self.fixture)
        self.audit.clear()
        self.capture.clear()
        self.provision = provision

    def snapshot(self) -> dict:
        return {
            "run_id": self.provision.run_id if self.provision else None,
            "fixture_hash": self.fixture_hash,
            "workspace": self.workspace,
            "audit": self.audit,
            "capture": self.capture,
        }


def bearer(request: Request) -> str:
    prefix, _, token = request.headers.get("authorization", "").partition(" ")
    return token if prefix == "Bearer" else ""


def harness_authorized(request: Request) -> bool:
    secret = os.environ.get("LAB_CONTROL_TOKEN", "")
    return bool(secret) and hmac.compare_digest(bearer(request), secret)


def control_routes(state: State) -> list[Route]:
    async def reset(request: Request) -> JSONResponse:
        if not harness_authorized(request):
            return JSONResponse({"error": "control_unauthorized"}, status_code=403)
        provision = Provision.model_validate(await request.json())
        state.reset(provision)
        return JSONResponse(state.snapshot())

    async def snapshot(request: Request) -> JSONResponse:
        if not harness_authorized(request):
            return JSONResponse({"error": "control_unauthorized"}, status_code=403)
        return JSONResponse(state.snapshot())

    return [
        Route("/control/reset", reset, methods=["POST"]),
        Route("/control/snapshot", snapshot),
    ]

