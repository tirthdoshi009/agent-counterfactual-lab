from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lab.control import State, bearer


def create_app(state: State) -> Starlette:
    async def capture(request: Request) -> JSONResponse:
        body = await request.json()
        provision = state.provision
        if (
            not provision or bearer(request) not in provision.identities
            or body.get("run_id") != provision.run_id
        ):
            return JSONResponse({"error": "invalid_identity_or_run"}, status_code=403)
        if (
            set(body) != {"run_id", "call_id", "payload"}
            or not isinstance(body["payload"], str)
            or len(body["payload"]) > 4096
        ):
            return JSONResponse({"error": "invalid_capture"}, status_code=400)
        state.capture.append(body)
        return JSONResponse({"captured": True})

    return Starlette(routes=[Route("/capture", capture, methods=["POST"])])

