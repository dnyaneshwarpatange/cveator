from datetime import UTC, datetime
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    api_docs_enabled: bool = True
    allowed_hosts_csv: str = "localhost,127.0.0.1,testserver,api"

    jwt_secret: SecretStr = SecretStr("development-only-secret-not-for-production")
    jwt_issuer: str = "cve-monitor-api"
    jwt_audience: str = "cve-monitor-web"
    jwt_access_token_minutes: int = Field(default=30, ge=5, le=1_440)

    payment_provider: str = ""
    billing_plans_json: str = "{}"

    database_url: str = "postgresql+psycopg://cve_monitor:change-me@localhost:5432/cve_monitor"
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_pool_timeout_seconds: int = Field(default=30, ge=1, le=120)
    database_pool_recycle_seconds: int = Field(default=1_800, ge=60, le=86_400)
    redis_url: str = "redis://localhost:6379/0"
    dependency_timeout_seconds: float = Field(default=2, gt=0, le=10)
    auth_rate_limit_attempts: int = Field(default=10, ge=1, le=100)
    auth_rate_limit_window_seconds: int = Field(default=900, ge=60, le=86_400)
    webhook_max_body_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)

    object_storage_enabled: bool = False
    storage_endpoint_url: str = ""
    storage_region: str = "local"
    storage_bucket: str = "cve-monitor"
    storage_access_key: SecretStr | None = None
    storage_secret_key: SecretStr | None = None

    email_delivery_enabled: bool = False
    email_from_address: str = ""
    email_from_name: str = "CVE Monitor"
    public_app_url: str = "http://localhost:3000"
    smtp_host: str = ""
    smtp_port: int = Field(default=25, ge=1, le=65_535)
    smtp_security: Literal["none", "starttls", "tls"] = "none"
    smtp_username: str = ""
    smtp_password: SecretStr | None = None
    smtp_timeout_seconds: float = Field(default=15, gt=0, le=120)
    notification_batch_limit: int = Field(default=500, ge=1, le=10_000)
    notification_max_batches_per_run: int = Field(default=20, ge=1, le=100)
    digest_hour_utc: int = Field(default=3, ge=0, le=23)
    digest_minute_utc: int = Field(default=0, ge=0, le=59)

    nvd_api_key: SecretStr | None = None
    nvd_results_per_page: int = Field(default=2_000, ge=1, le=2_000)
    nvd_initial_sync_start: datetime = datetime(2000, 1, 1, tzinfo=UTC)
    nvd_cpe_results_per_page: int = Field(default=10_000, ge=1, le=10_000)
    nvd_cpe_initial_sync_start: datetime = datetime(2000, 1, 1, tzinfo=UTC)
    mitre_delta_log_url: str = (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
    )
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_csv_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

    @field_validator("nvd_initial_sync_start", "nvd_cpe_initial_sync_start")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("NVD initial sync timestamps must include a timezone")
        return value.astimezone(UTC)

    @property
    def nvd_rate_limit_interval_seconds(self) -> float:
        """NVD permits 50 requests/30s with a key and 5/30s without one."""
        return 0.6 if self.nvd_api_key else 6.0

    @property
    def allowed_hosts(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts_csv.split(",") if host.strip()]

    def validate_runtime_security(self) -> None:
        secret = self.jwt_secret.get_secret_value()
        insecure_values = {
            "",
            "development-only-secret-not-for-production",
            "replace-with-a-random-64-character-secret-before-production",
        }
        if self.app_env.lower() != "development" and (
            secret in insecure_values or secret.startswith("replace-") or len(secret) < 32
        ):
            raise RuntimeError(
                "JWT_SECRET must be a unique, random value of at least 32 characters"
            )
        if self.app_env.lower() != "development" and "*" in self.allowed_hosts:
            raise RuntimeError("ALLOWED_HOSTS_CSV cannot contain '*' outside development")
        self.validate_email_configuration()
        self.validate_storage_configuration()

    def validate_email_configuration(self) -> None:
        if not self.email_delivery_enabled:
            return
        if not self.smtp_host.strip():
            raise RuntimeError("SMTP_HOST is required when email delivery is enabled")
        if not self.email_from_address.strip():
            raise RuntimeError("EMAIL_FROM_ADDRESS is required when email delivery is enabled")
        has_username = bool(self.smtp_username.strip())
        has_password = bool(self.smtp_password and self.smtp_password.get_secret_value())
        if has_username != has_password:
            raise RuntimeError("SMTP_USERNAME and SMTP_PASSWORD must be configured together")

    def validate_storage_configuration(self) -> None:
        if not self.object_storage_enabled:
            return
        required = {
            "STORAGE_ENDPOINT_URL": self.storage_endpoint_url,
            "STORAGE_BUCKET": self.storage_bucket,
            "STORAGE_ACCESS_KEY": (
                self.storage_access_key.get_secret_value() if self.storage_access_key else ""
            ),
            "STORAGE_SECRET_KEY": (
                self.storage_secret_key.get_secret_value() if self.storage_secret_key else ""
            ),
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise RuntimeError(f"Object storage settings are missing: {', '.join(missing)}")


@lru_cache
def get_settings() -> Settings:
    return Settings()
