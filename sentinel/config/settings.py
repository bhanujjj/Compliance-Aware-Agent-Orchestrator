"""
sentinel/config/settings.py
Central, validated settings powered by pydantic-settings.
All values are read from environment variables or the .env file.
A ValidationError is raised at startup if a required field is missing or wrong type.
Usage:
    from sentinel.config.settings import settings
    print(settings.AUDIT_DB_PATH)
"""
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class SentinelSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",       # ignore unknown env vars silently
    )

    # ── OpenRouter / LLM ──────────────────────────────────────────────────────
    OPENROUTER_API_KEY: str = Field(default="", description="OpenRouter API key")

    # ── Paths ─────────────────────────────────────────────────────────────────
    PROJECT_ROOT: Path = Field(
        default=Path(__file__).parent.parent.parent,
        description="Absolute path to the project root directory"
    )
    AUDIT_DB_PATH: Path = Field(
        default=Path("data/audit.db"),
        description="Path to the SQLite audit database"
    )
    POLICY_CONFIG_PATH: Path = Field(
        default=Path("sentinel/config/policy_cyber.yaml"),
        description="Path to the YAML policy configuration file"
    )

    # ── LangSmith Observability ───────────────────────────────────────────────
    LANGCHAIN_TRACING_V2: bool = Field(default=False, description="Enable LangSmith tracing")
    LANGCHAIN_API_KEY: str = Field(default="", description="LangSmith API key")
    LANGCHAIN_PROJECT: str = Field(default="sentinel-orchestrator", description="LangSmith project name")

    # ── Behaviour ─────────────────────────────────────────────────────────────
    MAX_RETRIES: int = Field(default=2, ge=0, le=10, description="Max policy engine retries per incident")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level: DEBUG | INFO | WARNING | ERROR")
    ESCALATION_THRESHOLD: float = Field(default=8.0, ge=0.0, le=10.0, description="Severity score threshold for auto-escalation")
    WS_PUSH_INTERVAL_SECONDS: int = Field(default=3, ge=1, description="WebSocket push interval in seconds")

    # ── Validators ────────────────────────────────────────────────────────────
    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}, got '{v}'")
        return v.upper()

    @field_validator("AUDIT_DB_PATH", "POLICY_CONFIG_PATH", mode="before")
    @classmethod
    def resolve_paths(cls, v) -> Path:
        return Path(v)

# Singleton — import this everywhere
settings = SentinelSettings()
