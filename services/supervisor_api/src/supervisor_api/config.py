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
    max_payload_bytes: int = Field(default=65536, alias="MAX_PAYLOAD_BYTES")
    # Public demo: let anonymous visitors hit POST /v1/actions/evaluate?dry_run=true
    # so the landing scanner shows value before signup. Gated by IP-based rate limit.
    public_demo_enabled: bool = Field(default=True, alias="PUBLIC_DEMO_ENABLED")
    public_demo_rate_limit_per_minute: int = Field(default=10, alias="PUBLIC_DEMO_RATE_LIMIT_PER_MINUTE")
    # Comma-separated list. Defaults cover both the old :3000 layout and the CLI's :3099.
    cors_origins_raw: str = Field(
        default="http://localhost:3000,http://localhost:3099",
        alias="CORS_ORIGINS",
    )

    # Billing — Stripe Checkout subscription flow.
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_price_id: str = Field(default="", alias="STRIPE_PRICE_ID")
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")

    # Email — magic link delivery via Resend.
    resend_api_key: str = Field(default="", alias="RESEND_API_KEY")
    resend_from: str = Field(default="vibefixing <noreply@vibefixing.me>", alias="RESEND_FROM")

    # Public site URL — used to build magic-link callback URLs in emails.
    site_url: str = Field(default="http://localhost:3099", alias="SITE_URL")

    @property
    def billing_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_price_id)

    @property
    def email_enabled(self) -> bool:
        return bool(self.resend_api_key)

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins_raw.split(",") if o.strip()]

    @property
    def resolved_policy_path(self) -> Path:
        p = Path(self.policy_path)
        if p.is_absolute():
            return p
        return self.repo_root / self.policy_path

    @property
    def repo_root(self) -> Path:
        """Walk up from cwd to find the repo root (contains pnpm-workspace.yaml)."""
        here = Path.cwd().resolve()
        for candidate in [here, *here.parents]:
            if (candidate / "pnpm-workspace.yaml").exists():
                return candidate
        return here


@lru_cache
def get_settings() -> Settings:
    return Settings()
