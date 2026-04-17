from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite:///./aic.sqlite3", alias="DATABASE_URL")
    evidence_hmac_secret: str = Field(default="dev-hmac-secret-change-me", alias="EVIDENCE_HMAC_SECRET")
    policy_path: str = Field(default="packages/policies/refund.base.v1.yaml", alias="POLICY_PATH")
    app_env: str = Field(default="dev", alias="APP_ENV")
    require_auth: bool = Field(default=False, alias="REQUIRE_AUTH")
    admin_bootstrap_token: str = Field(default="", alias="ADMIN_BOOTSTRAP_TOKEN")
    webhook_secret: str = Field(default="dev-webhook-secret-change-me", alias="WEBHOOK_SECRET")

    @property
    def resolved_policy_path(self) -> Path:
        p = Path(self.policy_path)
        if p.is_absolute():
            return p
        # Walk up from cwd to find the repo root (contains pnpm-workspace.yaml)
        here = Path.cwd().resolve()
        for candidate in [here, *here.parents]:
            if (candidate / "pnpm-workspace.yaml").exists():
                return candidate / self.policy_path
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()
