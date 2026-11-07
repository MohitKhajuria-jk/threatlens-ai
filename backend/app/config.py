"""App settings, read from environment variables or backend/.env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Preset endpoints for OpenAI-compatible chat APIs. Any of them can be overridden with LLM_BASE_URL.
PROVIDERS: dict[str, dict[str, str]] = {
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-3.5-flash",
        # Used automatically while the main model is overloaded or rate-limited.
        "fallback_model": "gemini-3.1-flash-lite",
        "label": "Google Gemini",
    },
    "openai": {"base_url": "https://api.openai.com/v1", "model": "", "label": "OpenAI"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "model": "", "label": "Anthropic Claude"},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "llama3.1", "label": "Ollama (local)"},
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    # Language model (investigation reports and the analyst chat)
    llm_provider: str = "gemini"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_fallback_model: str = ""  # "none" turns the backup model off
    llm_reasoning_effort: str = ""  # low | medium | high | default; empty means "low" on Gemini
    llm_timeout_seconds: float = 150
    max_agent_steps: int = 8

    # Threat intelligence. The free feeds need no key; the two APIs are optional.
    intel_feeds_enabled: bool = True
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    # How many alert IPs to check with AbuseIPDB after each analysis (free tier: 1,000 checks a day).
    abuseipdb_max_per_analysis: int = 20

    # Timezone for log lines that don't include one (Linux syslog, Windows Firewall).
    # An IANA name like "Asia/Kolkata"; empty means this computer's timezone.
    log_timezone: str = ""
    max_upload_mb: int = 50
    # Compressed logs (.gz, .zip) may expand to at most this much; it stops "zip bombs".
    max_unpacked_mb: int = 200
    # Largest file "Check a file" accepts. Files are only hashed, never stored.
    max_check_mb: int = 200

    frontend_url: str = "http://localhost:5173"
    data_dir: Path = BACKEND_DIR / "data"

    @property
    def provider(self) -> dict[str, str]:
        return PROVIDERS.get(self.llm_provider.lower(), PROVIDERS["gemini"])

    @property
    def resolved_base_url(self) -> str:
        return (self.llm_base_url or self.provider["base_url"]).rstrip("/")

    @property
    def resolved_model(self) -> str:
        return self.llm_model or self.provider["model"]

    @property
    def resolved_fallback_model(self) -> str:
        if self.llm_fallback_model.strip().lower() == "none":
            return ""
        fallback = self.llm_fallback_model.strip() or self.provider.get("fallback_model", "")
        return "" if fallback == self.resolved_model else fallback

    @property
    def resolved_reasoning_effort(self) -> str:
        value = self.llm_reasoning_effort.strip().lower()
        if value in ("none", "off", "default"):
            return ""
        if value:
            return value
        return "low" if self.llm_provider.lower() == "gemini" else ""

    @property
    def llm_ready(self) -> bool:
        needs_key = self.llm_provider.lower() != "ollama"
        return bool(self.resolved_model) and (bool(self.llm_api_key) or not needs_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
