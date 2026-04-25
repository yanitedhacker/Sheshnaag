"""APScheduler wrapper that produces a per-tenant brief on a cadence.

Mirrors the FeedScheduler pattern. Disabled by default — opt in via
``BRIEF_SCHEDULER_ENABLED=true``. Cadence configurable via
``BRIEF_INTERVAL_HOURS`` (default 24).
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.models.v2 import Tenant
from app.services.brief_service import BriefService

logger = logging.getLogger(__name__)


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BriefScheduler:
    """APScheduler wrapper that emits scheduled briefs per active tenant."""

    def __init__(self) -> None:
        self.scheduler: Optional[AsyncIOScheduler] = None

    @property
    def enabled(self) -> bool:
        return _is_truthy(os.getenv("BRIEF_SCHEDULER_ENABLED", ""))

    @property
    def interval_hours(self) -> int:
        try:
            return max(1, int(os.getenv("BRIEF_INTERVAL_HOURS", "24")))
        except ValueError:
            return 24

    def start(self) -> None:
        if not self.enabled:
            logger.info("Brief scheduler disabled by configuration")
            return
        if self.scheduler:
            return

        self.scheduler = AsyncIOScheduler()
        trigger = IntervalTrigger(hours=self.interval_hours)
        self.scheduler.add_job(
            self._tick,
            trigger=trigger,
            id="brief_generation_job",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=300,
            next_run_time=utc_now(),
        )
        self.scheduler.start()
        logger.info("Brief scheduler started (interval=%dh)", self.interval_hours)

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
            logger.info("Brief scheduler stopped")

    async def _tick(self) -> None:
        logger.info("Brief scheduler tick")
        session = SessionLocal()
        try:
            tenants = session.query(Tenant).filter(Tenant.is_active.is_(True)).all()
            service = BriefService(session)
            for tenant in tenants:
                try:
                    service.generate_brief(tenant, brief_type="scheduled")
                except Exception as exc:  # pragma: no cover - per-tenant best-effort
                    logger.warning("brief generation failed for tenant=%s: %s", tenant.slug, exc)
            session.commit()
        except Exception as exc:  # pragma: no cover - infra-dependent
            logger.exception("Brief scheduler tick failed: %s", exc)
            session.rollback()
        finally:
            session.close()
