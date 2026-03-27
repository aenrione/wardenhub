from __future__ import annotations

import asyncio

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from wardenhub_agent import __version__

log = structlog.get_logger()

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def setup_scheduler(pushgateway_url: str, cleanup_threshold_seconds: int) -> AsyncIOScheduler:
    from wardenhub_coordinator.cleanup import cleanup_stale_metrics

    scheduler = get_scheduler()

    async def run_cleanup() -> None:
        log.info("running Pushgateway cleanup")
        await cleanup_stale_metrics(pushgateway_url, cleanup_threshold_seconds)

    async def run_cluster_checks() -> None:
        log.debug("cluster checks: no providers configured for Phase 1")

    scheduler.add_job(
        run_cleanup,
        trigger="interval",
        hours=1,
        id="pushgateway_cleanup",
        replace_existing=True,
    )

    scheduler.add_job(
        run_cluster_checks,
        trigger="interval",
        seconds=cleanup_threshold_seconds,
        id="cluster_checks",
        replace_existing=True,
    )

    return scheduler
