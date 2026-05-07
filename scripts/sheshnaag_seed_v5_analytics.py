#!/usr/bin/env python3
"""V5 W3c — seed synthetic analytics dataset.

Used by the V5 kill-criteria gate item #5 ("analytics renders with
≥1000 synthetic cases"). Run after migrations are at v5a07 head.

Usage:
    python scripts/sheshnaag_seed_v5_analytics.py [--n-cases 1000]
                                                  [--tenant-slug demo]
                                                  [--seed 1337]
                                                  [--window-days 60]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.services.v5_analytics_seeder import V5AnalyticsSeeder


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tenant-slug", default=None)
    p.add_argument("--tenant-id", type=int, default=None)
    p.add_argument("--n-cases", type=int, default=1000)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--window-days", type=int, default=60)
    args = p.parse_args()

    session = SessionLocal()
    try:
        summary = V5AnalyticsSeeder(session).seed(
            tenant_id=args.tenant_id,
            tenant_slug=args.tenant_slug,
            n_cases=args.n_cases,
            seed=args.seed,
            window_days=args.window_days,
        )
    finally:
        session.close()

    print(f"tenant_id={summary.tenant_id}")
    print(f"cases_inserted={summary.cases_inserted}")
    print(f"transitions_inserted={summary.transitions_inserted}")
    print(f"findings_inserted={summary.findings_inserted}")
    print(f"ai_sessions_inserted={summary.ai_sessions_inserted}")
    print(f"audit_entries_inserted={summary.audit_entries_inserted}")
    print(f"skipped={summary.skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
