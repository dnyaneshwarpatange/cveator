import pytest
from pydantic import SecretStr

from app.api.auth import LoginRequest
from app.core.config import Settings
from app.scripts import seed_demo


def test_production_rejects_documented_placeholder_secret() -> None:
    settings = Settings(app_env="production", jwt_secret=SecretStr(
        "replace-with-a-unique-random-secret-of-at-least-32-characters"))
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        settings.validate_runtime_security()


def test_demo_identity_can_sign_in_and_seed_is_blocked_in_production(monkeypatch) -> None:
    assert LoginRequest(email=seed_demo.DEMO_EMAIL, password=seed_demo.DEMO_PASSWORD)
    monkeypatch.setattr(seed_demo, "get_settings", lambda: Settings(app_env="production"))
    with pytest.raises(SystemExit, match="only allowed in development"):
        seed_demo.main()
