"""
run_pipeline_local.py
---------------------
Run the detection pipeline locally without FastAPI / Cloud Foundry.

Usage::

    python -m scripts.run_pipeline_local

This is the ``make run`` entrypoint. It creates a :class:`Pipeline` and
runs ``run_forever()`` until interrupted (Ctrl-C / SIGTERM). Mock mode
auto-enables when the corresponding env vars are unset.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import asyncio

from src.common.config import settings
from src.common.logging import get_logger
from src.pipeline import Pipeline
from src.storage.migrations import apply_schema
from src.storage.pool import pool

logger = get_logger(__name__)


async def _main() -> None:
    logger.info(
        "run_pipeline_local.start",
        extra={
            "mock_api": settings.mock_api,
            "mock_webhook": settings.mock_webhook,
            "mock_hana": settings.mock_hana,
            "poll_interval_s": settings.poll_interval_seconds,
        },
    )

    await pool.initialize()
    await apply_schema()

    pipeline = Pipeline()
    try:
        await pipeline.run_forever()
    finally:
        await pool.close()
        logger.info("run_pipeline_local.stopped")


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
