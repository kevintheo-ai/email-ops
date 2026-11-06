import pytest

import injection_guard as guard


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    """No test reaches TypeSafe or your real config: no key, a temp config file, a temp guard log."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    cfg = tmp_path / "email-ops.toml"
    cfg.write_text(f'[guard]\nlog = "{tmp_path / "guard.jsonl"}"\n', encoding="utf-8")
    monkeypatch.setenv("EMAIL_OPS_CONFIG", str(cfg))
    guard._client.cache_clear()
    return cfg
