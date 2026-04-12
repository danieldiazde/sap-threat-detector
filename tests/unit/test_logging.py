"""Unit tests for src/common/logging.py."""

from __future__ import annotations

import logging

from src.common.logging import get_logger


class TestGetLogger:
    def test_returns_logger(self):
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_idempotent(self):
        """Calling get_logger twice returns the same Logger instance."""
        a = get_logger("test.idem")
        b = get_logger("test.idem")
        assert a is b

    def test_logger_has_handlers(self):
        get_logger("test.handlers")
        root = logging.getLogger()
        assert len(root.handlers) > 0
