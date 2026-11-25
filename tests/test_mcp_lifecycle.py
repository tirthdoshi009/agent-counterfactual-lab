import asyncio
import logging
import warnings

from mcp.server.streamable_http import StreamableHTTPServerTransport

from lab.control import State
from lab.gateway import create_app


def test_gateway_settings_resolve_lifespan_without_warnings():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        create_app(State(), "http://127.0.0.1:1", ["127.0.0.1:*"])


async def test_expected_stateless_transport_termination_does_not_log_error(caplog):
    caplog.set_level(logging.ERROR, logger="mcp.server.streamable_http")
    transport = StreamableHTTPServerTransport(mcp_session_id=None, is_json_response_enabled=True)
    async with transport.connect():
        await transport.terminate()
        await asyncio.sleep(0)
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]


async def test_unexpected_stream_closure_still_logs_error(caplog):
    caplog.set_level(logging.ERROR, logger="mcp.server.streamable_http")
    transport = StreamableHTTPServerTransport(mcp_session_id=None, is_json_response_enabled=True)
    async with transport.connect():
        await transport._write_stream_reader.aclose()
        await asyncio.sleep(0)
    assert any(
        "Unexpected closure of read stream" in record.message
        and record.levelno >= logging.ERROR
        for record in caplog.records
    )
