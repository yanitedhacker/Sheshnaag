"""Background scheduler for feed ingestion."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from app.core.time import utc_now
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.core.database import SessionLocal
from app.ingestion.feed_aggregator import FeedAggregator

logger = logging.getLogger(__name__)


class FeedScheduler:
    """APScheduler wrapper to run feed sync jobs."""

    def __init__(self):
        self.scheduler: Optional[AsyncIOScheduler] = None

    def start(self):
        if not settings.feed_scheduler_enabled:
            logger.info("Feed scheduler disabled by configuration")
            return

        if self.scheduler:
            return

        self.scheduler = AsyncIOScheduler()
        trigger = IntervalTrigger(hours=settings.feed_update_interval_hours)
        self.scheduler.add_job(
            self._run_sync,
            trigger=trigger,
            id="feed_sync_job",
            max_instances=settings.feed_scheduler_max_instances,
            coalesce=True,
            misfire_grace_time=300,
            next_run_time=utc_now(),
        )
        self.scheduler.start()
        logger.info("Feed scheduler started")

    def shutdown(self):
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
            logger.info("Feed scheduler stopped")

    async def _run_sync(self):
        logger.info("Feed scheduler tick: running incremental sync")
        session = SessionLocal()
        try:
            aggregator = FeedAggregator(session)
            await aggregator.sync_with_state(days=7, exploit_limit=2000)
        except Exception as e:
            logger.exception("Scheduled feed sync failed: %s", e)
        finally:
            session.close()
