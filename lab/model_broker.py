"""Credential-bearing upstream client; instantiated only inside the trusted RPC broker."""

import ipaddress
import json
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from lab.adapters.tool_calling import ModelTurn, ProviderError, ToolProposal


class OpenAICompatibleBroker:
    def __init__(
        self, *, endpoint: str, approved_endpoints: frozenset[str], model: str, credential: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        url = urlsplit(endpoint)
        if (
            endpoint not in approved_endpoints or url.scheme != "https"
            or not url.hostname or url.username or url.password or url.query or url.fragment
            or url.port not in (None, 443) or not url.path.endswith("/chat/completions")
            or any(character.isspace() for character in endpoint)
        ):
            raise ValueError("An exact operator-approved HTTPS chat/completions endpoint is required")
        try:
            ipaddress.ip_address(url.hostname)
        except ValueError:
            if "." not in url.hostname or url.hostname.endswith(".localhost"):
                raise ValueError("A provider hostname is required") from None
        else:
            raise ValueError("Literal network addresses are not provider endpoints")
        if not model or len(model) > 160 or any(ord(c) < 32 for c in model):
            raise ValueError("An explicit bounded model identifier is required")
        if not credential or len(credential) > 4096 or any(ord(c) < 33 for c in credential):
            raise ValueError("An explicit trusted-host credential is required")
        if credential in endpoint or credential in model:
            raise ValueError("Credential must not occur in public provider configuration")
        self.endpoint, self.model = endpoint, model
        self._credential, self._transport = credential, transport

    @property
    def metadata(self) -> dict:
        return {
            "provider": "openai-compatible", "model": self.model, "endpoint": self.endpoint,
            "live_model": True, "settings": {
                "temperature": 0, "store": False, "tool_choice": "auto",
                "parallel_tool_calls": False, "response_cache": "none_in_harness",
            },
        }

    async def complete(self, messages: list[dict], tools: list[dict],
                       max_output_tokens: int) -> ModelTurn:
        if not 1 <= max_output_tokens <= 1024:
            raise ProviderError("invalid_output_token_limit")
        payload = {
            "model": self.model, "messages": messages, "tools": tools,
            "max_tokens": max_output_tokens, **{
                k: v for k, v in self.metadata["settings"].items() if k != "response_cache"
            },
        }
        try:
            async with httpx.AsyncClient(
                trust_env=False, follow_redirects=False, timeout=15, transport=self._transport,
            ) as client:
                async with client.stream(
                    "POST", self.endpoint, json=payload,
                    headers={"Authorization": f"Bearer {self._credential}"},
                ) as response:
                    if response.status_code != 200:
                        raise ProviderError(f"provider_http_status:{response.status_code}")
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > 131072:
                            raise ProviderError("provider_response_too_large")
            raw = json.loads(data)
            if len(raw["choices"]) != 1:
                raise ProviderError("provider_requires_one_choice")
            choice = raw["choices"][0]
            message = choice["message"]
            proposals = []
            for entry in message.get("tool_calls", []):
                if entry["type"] != "function":
                    raise ProviderError("unsupported_provider_tool_type")
                proposals.append(ToolProposal(
                    id=entry["id"], name=entry["function"]["name"],
                    arguments=json.loads(entry["function"]["arguments"]),
                ))
            usage = raw["usage"]
            turn = ModelTurn(
                text=message.get("content") or "", tool_calls=proposals,
                input_tokens=usage["prompt_tokens"], output_tokens=usage["completion_tokens"],
                finish_reason=choice["finish_reason"], response_id=raw["id"],
            )
            if (
                type(usage["total_tokens"]) is not int
                or usage["total_tokens"] != turn.input_tokens + turn.output_tokens
            ):
                raise ProviderError("provider_usage_conflict")
            if self._credential in turn.model_dump_json():
                raise ProviderError("upstream_credential_in_response")
            return turn
        except httpx.HTTPError:
            raise ProviderError("provider_transport_failure") from None
        except (KeyError, TypeError, ValueError, AttributeError, IndexError, ValidationError):
            raise ProviderError("invalid_provider_response_or_usage") from None
