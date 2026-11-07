import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable

import pytest

# Keep test databases out of backend/data, even when the app module is imported.
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="threatlens-test-"))
os.environ.setdefault("INTEL_FEEDS_ENABLED", "false")

from app.config import Settings  # noqa: E402


class ScriptedModel:
    """Stands in for the LLM: returns prepared replies in order and records every request."""

    label = "Scripted test model"
    active_model = "scripted"

    def __init__(self, replies: list[dict[str, Any] | Callable[[list[dict[str, Any]]], dict[str, Any]]]):
        self.replies = list(replies)
        self.calls: list[dict[str, Any]] = []

    async def chat(self, messages, tools, tool_choice="auto"):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools, "tool_choice": tool_choice})
        if not self.replies:
            return {"role": "assistant", "content": "No more scripted replies."}
        reply = self.replies.pop(0)
        return reply(messages) if callable(reply) else reply


def tool_call(name: str, args: dict[str, Any], call_id: str = "call_1") -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def answer(text: str) -> dict[str, Any]:
    return {"role": "assistant", "content": text}


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(_env_file=None, data_dir=tmp_path, llm_api_key="test-key", intel_feeds_enabled=False, log_timezone="UTC",
                    abuseipdb_api_key="", virustotal_api_key="")


NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
