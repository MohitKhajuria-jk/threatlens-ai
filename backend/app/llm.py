"""Chat calls to any OpenAI-compatible API (Gemini, OpenAI, Anthropic, Ollama).

Uses plain HTTP rather than an SDK, so assistant messages are kept exactly as the
API returned them. Gemini 3 attaches "thought signatures" to tool calls that must
be sent back unchanged on the next request; keeping the raw message does that.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol

import httpx

from .config import Settings

log = logging.getLogger("llm")


class LLMError(Exception):
    """A problem talking to the model, with a message that can be shown to the user."""


class ChatModel(Protocol):
    label: str

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], tool_choice: str = "auto") -> dict[str, Any]: ...


def _error_detail(response: httpx.Response) -> str:
    """The API's own error message, e.g. from {"error": {"message": ...}} or a list of those."""
    try:
        data = response.json()
        if isinstance(data, list) and data:
            data = data[0]
        message = data.get("error", {}).get("message") if isinstance(data, dict) else None
        if message:
            return str(message)[:300]
    except ValueError:
        pass
    return response.text[:300]


def _retry_after(response: httpx.Response) -> float:
    try:
        return min(10.0, float(response.headers.get("retry-after", "3")))
    except ValueError:
        return 3.0


class OpenAICompatibleClient:
    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None):
        self.base_url = settings.resolved_base_url
        self.model = settings.resolved_model
        self.fallback_model = settings.resolved_fallback_model
        self.api_key = settings.llm_api_key
        self.provider_label = settings.provider["label"]
        self.provider = settings.llm_provider.lower()
        self._fallback_until = 0.0
        self.reasoning_effort = settings.resolved_reasoning_effort
        self.timeout = httpx.Timeout(settings.llm_timeout_seconds, connect=15.0)
        self._http = http or httpx.AsyncClient()

    @property
    def using_fallback(self) -> bool:
        return bool(self.fallback_model) and time.time() < self._fallback_until

    @property
    def active_model(self) -> str:
        return self.fallback_model if self.using_fallback else self.model

    @property
    def label(self) -> str:
        if self.using_fallback:
            return f"{self.provider_label} · {self.fallback_model} (backup while {self.model} is busy)"
        return f"{self.provider_label} · {self.model}"

    @property
    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/{path}"
        for attempt in range(3):
            started = time.monotonic()
            try:
                r = await self._http.post(url, json=body, headers=self.headers, timeout=self.timeout)
            except httpx.ConnectTimeout as err:
                log.warning("Couldn't connect to %s within 15s", self.base_url)
                raise LLMError(
                    "Couldn't connect to the model API within 15 seconds. Check your internet connection, VPN or firewall."
                ) from err
            except httpx.TimeoutException as err:
                # Not retried: resending the same request would only double the wait.
                log.warning("Model call timed out after %.0fs", time.monotonic() - started)
                raise LLMError(
                    f"The model didn't answer within {self.timeout.read:.0f} seconds. "
                    "This usually means a slow connection or a busy free tier. Try again in a moment."
                ) from err
            except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.ConnectError) as err:
                # Dropped connections are retried once, which helps on unstable networks.
                log.warning("Model connection failed (%s), attempt %d", type(err).__name__, attempt + 1)
                if attempt < 1:
                    await asyncio.sleep(1.0)
                    continue
                raise LLMError(f"Couldn't reach the model API at {self.base_url}. Check your internet connection.") from err
            except httpx.HTTPError as err:
                raise LLMError(f"Couldn't reach the model API at {self.base_url}. Check your internet connection.") from err
            log.info("Model replied in %.1fs (HTTP %d, %d messages)", time.monotonic() - started, r.status_code, len(body.get("messages", [])))
            busy = r.status_code in (429, 503)
            if busy and self.fallback_model and body.get("model") != self.fallback_model:
                # Free-tier limits and overload are per model, so switch straight to the backup
                # model and keep using it for 10 minutes instead of waiting on the busy one.
                log.warning("%s is busy (HTTP %d); using %s for the next 10 minutes", body.get("model"), r.status_code, self.fallback_model)
                self._fallback_until = time.time() + 600
                body = {**body, "model": self.fallback_model}
                continue
            if r.status_code == 429 or r.status_code >= 500:
                if attempt < 2:
                    await asyncio.sleep(_retry_after(r) if r.status_code == 429 else 1.5)
                    continue
                if r.status_code == 429:
                    raise LLMError(
                        "The model's rate limit was reached (on Gemini's free tier this is a few requests a minute). "
                        "Wait a minute and ask again."
                    )
                if r.status_code == 503:
                    raise LLMError(
                        f"Google reports high demand for {body.get('model')} right now. Try again in a few minutes, "
                        "or set LLM_MODEL in backend/.env to another model."
                    )
                raise LLMError(f"The model API had a temporary error ({r.status_code}). Try again in a moment.")
            detail = _error_detail(r) if r.status_code >= 400 else ""
            # Gemini reports a bad key as 400 "API key not valid"; others use 401/403.
            if r.status_code in (401, 403) or "api key" in detail.lower() or "API_KEY_INVALID" in r.text:
                raise LLMError("The model API rejected the API key. Check LLM_API_KEY in backend/.env.")
            if r.status_code == 404:
                raise LLMError(f"The model '{body.get('model')}' wasn't found. Check LLM_MODEL in backend/.env.")
            if r.status_code >= 400:
                raise LLMError(f"The model API returned an error ({r.status_code}): {detail}")
            return r.json()
        raise LLMError("The model API couldn't be reached.")

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], tool_choice: str = "auto") -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.active_model, "messages": messages}
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice
        data = await self._post("chat/completions", body)
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as err:
            raise LLMError("The model returned an empty response. Try asking again.") from err
