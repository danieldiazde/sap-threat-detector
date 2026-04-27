"""Unit tests for src/common/config.py."""

from __future__ import annotations

import os
from unittest.mock import patch

from src.common.config import Settings


class TestSettings:
    def test_from_env_defaults(self):
        """With no env vars set, Settings should use defaults and be fully mock."""
        with patch.dict(os.environ, {}, clear=True):
            s = Settings.from_env()
        assert s.mock_api is True
        assert s.mock_webhook is True
        assert s.mock_hana is True
        assert s.model_type == "isolation_forest"
        assert s.model_contamination == 0.05

    def test_mock_api_false_when_url_set(self):
        with patch.dict(os.environ, {"SAP_API_URL": "https://example.com"}, clear=True):
            s = Settings.from_env()
        assert s.mock_api is False

    def test_mock_webhook_false_when_api_url_set(self):
        # /alert lives on the SAP API itself, so mock_webhook tracks SAP_API_URL.
        with patch.dict(os.environ, {"SAP_API_URL": "https://api.example.com"}, clear=True):
            s = Settings.from_env()
        assert s.mock_webhook is False

    def test_mock_hana_false_when_host_set(self):
        with patch.dict(os.environ, {"HANA_HOST": "host.hana.cloud"}, clear=True):
            s = Settings.from_env()
        assert s.mock_hana is False

    def test_is_production(self):
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=True):
            s = Settings.from_env()
        assert s.is_production is True

    def test_is_not_production(self):
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=True):
            s = Settings.from_env()
        assert s.is_production is False

    def test_frozen(self):
        """Settings should be immutable."""
        with patch.dict(os.environ, {}, clear=True):
            s = Settings.from_env()
        import pytest
        with pytest.raises(AttributeError):
            s.model_type = "dbscan"  # type: ignore[misc]

    def test_invalid_int_raises(self):
        import pytest
        with patch.dict(os.environ, {"HANA_PORT": "abc"}, clear=True), pytest.raises(ValueError, match="not a valid int"):
            Settings.from_env()
