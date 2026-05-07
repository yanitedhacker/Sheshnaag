"""V5 W3c — synthetic analytics dataset seeder.

Generates a corpus of ``AnalysisCase`` rows + ``CaseStateTransition``
chains + ``BehaviorFinding`` rows + ``AISession`` rows + ``AuditLogEntry``
rows that exercise every aggregation in
:class:`app.services.team_analytics.TeamAnalyticsService`.

Used by the V5 kill-criteria gate item #5 ("analytics renders with
≥1000 synthetic cases"). Idempotent: re-running with the same
``run_id`` short-circuits.

Deliberately *not* attempting Merkle audit-chain integrity for
``AuditLogEntry`` rows — the team_analytics service only sums them up
and the kill-criteria check only requires non-zero histogram buckets.
A full chain seed would require linking every prior_hash, signing each
row, etc. That's the production audit-log pipeline's job; the analytics
seeder fakes deterministic byte fields with a counter-derived hash.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.tenancy import resolve_tenant
from app.core.time import utc_now
from app.models.capability import AuditLogEntry
from app.models.malware_lab import (
    AISession,
    AnalysisCase,
    BehaviorFinding,
    CaseStateTransition,
)
from app.services.case_workflow import CaseLifecycleState


logger = logging.getLogger(__name__)


_ANALYSTS: tuple[str, ...] = (
    "alex",
    "bri",
    "cara",
    "deej",
    "el",
    "fern",
    "gus",
    "harper",
)
_REVIEWERS: tuple[str, ...] = ("rina", "saul", "tia")
_LAB_LEAD = "lead"

_TECHNIQUES: tuple[str, ...] = (
    "T1059.003",  # Windows command shell
    "T1055.012",  # Process hollowing
    "T1547.001",  # Registry run-key persistence
    "T1027",  # Obfuscated files
    "T1071.001",  # Application Layer Protocol: web
    "T1486",  # Data encrypted for impact
    "T1003.001",  # OS credential dumping: LSASS
    "T1112",  # Modify registry
    "T1218.011",  # System binary proxy: rundll32
    "T1190",  # Exploit public-facing application
    "T1057",  # Process discovery
    "T1082",  # System information discovery
    "T1566.001",  # Phishing attachment
    "T1567.002",  # Exfil to cloud storage
    "T1497.003",  # Sandbox evasion: time-based
)

_CAPABILITIES: tuple[str, ...] = (
    "ai_assist.draft",
    "sandbox.detonate",
    "intel.enrich",
    "indicator.publish",
    "evidence.export",
    "policy.review",
)

_AUDIT_ACTIONS: tuple[str, ...] = ("issued", "approved", "exercised", "denied")


@dataclass
class SeedSummary:
    tenant_id: int
    cases_inserted: int
    transitions_inserted: int
    findings_inserted: int
    ai_sessions_inserted: int
    audit_entries_inserted: int
    skipped: bool


class V5AnalyticsSeeder:
    """Insert synthetic V5 analytics data for kill-criteria checks."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def seed(
        self,
        *,
        tenant_id: Optional[int] = None,
        tenant_slug: Optional[str] = None,
        n_cases: int = 1000,
        seed: int = 1337,
        window_days: int = 60,
    ) -> SeedSummary:
        tenant = resolve_tenant(
            self.session,
            tenant_id=tenant_id,
            tenant_slug=tenant_slug,
            default_to_demo=True,
        )

        # Idempotency: if we already have ≥ n_cases tagged with our
        # marker, short-circuit. Marker is stored in
        # ``custom_fields["v5_analytics_seed"] = True``.
        existing_marker = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id)
            .filter(
                AnalysisCase.custom_fields.contains({"v5_analytics_seed": True})
            )
            .count()
            if self._json_contains_supported()
            else 0
        )
        if existing_marker >= n_cases:
            logger.info(
                "v5 analytics seed skipped — %d already-seeded cases for tenant %d",
                existing_marker,
                tenant.id,
            )
            return SeedSummary(
                tenant_id=tenant.id,
                cases_inserted=0,
                transitions_inserted=0,
                findings_inserted=0,
                ai_sessions_inserted=0,
                audit_entries_inserted=0,
                skipped=True,
            )

        rng = random.Random(seed)
        end = utc_now()
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        window_start = end - timedelta(days=window_days)

        cases_inserted = 0
        transitions_inserted = 0
        findings_inserted = 0
        ai_sessions_inserted = 0
        audit_entries_inserted = 0

        for i in range(n_cases):
            analyst = rng.choice(_ANALYSTS)
            case_path = self._sample_case_path(rng, window_start, end)
            case = AnalysisCase(
                tenant_id=tenant.id,
                title=f"[seed#{i:04d}] {self._sample_title(rng)}",
                summary=self._sample_summary(rng),
                status="open" if case_path[-1][2] not in {
                    CaseLifecycleState.SHIPPED.value,
                    CaseLifecycleState.ARCHIVED.value,
                } else "closed",
                lifecycle_state=case_path[-1][2],
                state_changed_at=case_path[-1][0],
                state_changed_by=case_path[-1][3],
                priority=rng.choice(("low", "medium", "high", "critical")),
                analyst_name=analyst,
                specimen_ids=[],
                tags=["v5-analytics-seed"],
                metadata_json={"seeded_by": "V5AnalyticsSeeder", "seed": seed, "i": i},
                custom_fields={"v5_analytics_seed": True},
                created_at=case_path[0][0] - timedelta(hours=1),
                updated_at=case_path[-1][0],
            )
            self.session.add(case)
            self.session.flush()
            cases_inserted += 1

            for occurred_at, from_state, to_state, actor in case_path:
                self.session.add(
                    CaseStateTransition(
                        case_id=case.id,
                        from_state=from_state,
                        to_state=to_state,
                        actor=actor,
                        role_at_transition=self._role_for(actor),
                        reason="seeded",
                        occurred_at=occurred_at,
                    )
                )
                transitions_inserted += 1

            # 1-3 behavior findings per case with 1-3 ATT&CK techniques.
            n_findings = rng.choice((1, 1, 2, 3))
            for _ in range(n_findings):
                technique_choices = rng.sample(_TECHNIQUES, k=rng.choice((1, 2, 3)))
                self.session.add(
                    BehaviorFinding(
                        tenant_id=tenant.id,
                        analysis_case_id=case.id,
                        run_id=None,
                        finding_type=rng.choice(
                            ("network", "process", "registry", "memory", "filesystem")
                        ),
                        title=f"finding {rng.randint(1, 9999)}",
                        severity=rng.choice(("low", "medium", "high", "critical")),
                        confidence=round(rng.uniform(0.4, 0.99), 2),
                        status="published",
                        payload={
                            "attack_techniques": [
                                {
                                    "technique_id": tid,
                                    "confidence": round(rng.uniform(0.5, 0.95), 2),
                                    "rationale": "synthetic",
                                }
                                for tid in technique_choices
                            ],
                        },
                        created_at=rng_choice_in_window(rng, window_start, end),
                        updated_at=case_path[-1][0],
                    )
                )
                findings_inserted += 1

            # 0-2 AI sessions per case.
            n_ai = rng.choice((0, 1, 1, 2))
            for _ in range(n_ai):
                self.session.add(
                    AISession(
                        tenant_id=tenant.id,
                        analysis_case_id=case.id,
                        provider_key=rng.choice(("local-mlx", "openai", "anthropic")),
                        provider_mode=rng.choice(("draft", "review", "summarize")),
                        capability=rng.choice(_CAPABILITIES),
                        prompt="(synthetic prompt)",
                        grounding_digest="seed-" + hashlib.sha1(
                            f"{i}".encode("ascii")
                        ).hexdigest()[:32],
                        created_by=analyst,
                        status="completed",
                        review_state=rng.choice(
                            ("draft", "approved", "rejected", "draft", "approved")
                        ),
                        output_markdown="(synthetic output)",
                        output_payload={"i": i},
                        created_at=rng_choice_in_window(rng, window_start, end),
                        updated_at=case_path[-1][0],
                    )
                )
                ai_sessions_inserted += 1

        # Audit log entries — independent of cases, tagged with the
        # tenant via scope JSON. Fake the chain bytes deterministically.
        n_audit = max(n_cases * 3, 50)
        prev_hash = b"\x00" * 32
        for i in range(n_audit):
            actor = rng.choice(_ANALYSTS + _REVIEWERS + (_LAB_LEAD,))
            cap = rng.choice(_CAPABILITIES)
            action = rng.choice(_AUDIT_ACTIONS)
            entry_hash = hashlib.sha256(
                prev_hash + f"{i}-{actor}-{cap}-{action}".encode("ascii")
            ).digest()
            signed_at = rng_choice_in_window(rng, window_start, end)
            self.session.add(
                AuditLogEntry(
                    previous_hash=prev_hash,
                    entry_hash=entry_hash,
                    actor=actor,
                    action=action,
                    capability=cap,
                    artifact_id=f"seed-{i:06d}",
                    scope={"tenant_id": tenant.id},
                    payload={"seeded": True, "i": i},
                    signed_at=signed_at,
                    signer_cert=b"seed-cert",
                    signature=b"seed-sig",
                )
            )
            prev_hash = entry_hash
            audit_entries_inserted += 1

        self.session.commit()
        logger.info(
            "v5 analytics seed: tenant=%d cases=%d transitions=%d findings=%d ai=%d audit=%d",
            tenant.id,
            cases_inserted,
            transitions_inserted,
            findings_inserted,
            ai_sessions_inserted,
            audit_entries_inserted,
        )
        return SeedSummary(
            tenant_id=tenant.id,
            cases_inserted=cases_inserted,
            transitions_inserted=transitions_inserted,
            findings_inserted=findings_inserted,
            ai_sessions_inserted=ai_sessions_inserted,
            audit_entries_inserted=audit_entries_inserted,
            skipped=False,
        )

    # -- helpers ---------------------------------------------------------

    def _sample_case_path(
        self,
        rng: random.Random,
        window_start: datetime,
        window_end: datetime,
    ) -> List[Tuple[datetime, str, str, str]]:
        """Return a chronological list of (occurred_at, from, to, actor) edges.

        Branch shapes (weighted):
        - 60% full happy path (triage→analysis→review→ready_to_ship→shipped)
        - 15% archived from triage
        - 15% archived from analysis
        - 10% bounced (review→analysis→review→ready_to_ship→shipped)
        """
        triage_at = rng_choice_in_window(rng, window_start, window_end)
        analyst_actor = rng.choice(_ANALYSTS)
        senior = rng.choice(_ANALYSTS[:4])  # treat first half as senior_analyst
        reviewer = rng.choice(_REVIEWERS)

        roll = rng.random()
        if roll < 0.15:
            t1 = triage_at + timedelta(minutes=rng.randint(5, 90))
            return [(t1, CaseLifecycleState.TRIAGE.value, CaseLifecycleState.ARCHIVED.value, analyst_actor)]

        if roll < 0.30:
            t1 = triage_at + timedelta(minutes=rng.randint(10, 120))
            t2 = t1 + timedelta(hours=rng.randint(1, 8))
            return [
                (t1, CaseLifecycleState.TRIAGE.value, CaseLifecycleState.ANALYSIS.value, analyst_actor),
                (t2, CaseLifecycleState.ANALYSIS.value, CaseLifecycleState.ARCHIVED.value, analyst_actor),
            ]

        # Forward path
        t1 = triage_at + timedelta(minutes=rng.randint(10, 120))
        t2 = t1 + timedelta(hours=rng.randint(2, 36))
        t3 = t2 + timedelta(hours=rng.randint(1, 24))

        if roll < 0.40:
            # Bounced
            t4 = t3 + timedelta(hours=rng.randint(2, 24))
            t5 = t4 + timedelta(hours=rng.randint(1, 12))
            t6 = t5 + timedelta(hours=rng.randint(0, 6))
            return [
                (t1, CaseLifecycleState.TRIAGE.value, CaseLifecycleState.ANALYSIS.value, analyst_actor),
                (t2, CaseLifecycleState.ANALYSIS.value, CaseLifecycleState.REVIEW.value, analyst_actor),
                (t3, CaseLifecycleState.REVIEW.value, CaseLifecycleState.ANALYSIS.value, reviewer),
                (t4, CaseLifecycleState.ANALYSIS.value, CaseLifecycleState.REVIEW.value, analyst_actor),
                (t5, CaseLifecycleState.REVIEW.value, CaseLifecycleState.READY_TO_SHIP.value, reviewer),
                (t6, CaseLifecycleState.READY_TO_SHIP.value, CaseLifecycleState.SHIPPED.value, senior),
            ]

        t4 = t3 + timedelta(hours=rng.randint(1, 12))
        t5 = t4 + timedelta(hours=rng.randint(0, 6))
        return [
            (t1, CaseLifecycleState.TRIAGE.value, CaseLifecycleState.ANALYSIS.value, analyst_actor),
            (t2, CaseLifecycleState.ANALYSIS.value, CaseLifecycleState.REVIEW.value, analyst_actor),
            (t3, CaseLifecycleState.REVIEW.value, CaseLifecycleState.READY_TO_SHIP.value, reviewer),
            (t4, CaseLifecycleState.READY_TO_SHIP.value, CaseLifecycleState.SHIPPED.value, senior),
        ]

    def _role_for(self, actor: str) -> str:
        if actor in _REVIEWERS:
            return "reviewer"
        if actor == _LAB_LEAD:
            return "lab_lead"
        if actor in _ANALYSTS[:4]:
            return "senior_analyst"
        return "analyst"

    @staticmethod
    def _sample_title(rng: random.Random) -> str:
        adjectives = ("evasive", "noisy", "dropper", "ransom", "apt-style", "commodity")
        nouns = ("loader", "stealer", "implant", "downloader", "wiper")
        return f"{rng.choice(adjectives)} {rng.choice(nouns)}"

    @staticmethod
    def _sample_summary(rng: random.Random) -> str:
        return rng.choice(
            (
                "Sample dropped via phishing attachment.",
                "Captured during honeynet sweep.",
                "Submitted by partner SOC for triage.",
                "Recurring family observed across 3 customers.",
                "Novel technique chain — escalated for senior review.",
            )
        )

    def _json_contains_supported(self) -> bool:
        """SQLAlchemy ``JSON.contains`` requires Postgres jsonb. Fall
        back to brute count on SQLite. The fallback path returns 0,
        which means the seeder will re-insert on every run on SQLite.
        That is fine for dev/test."""
        bind = self.session.get_bind()
        return bind.dialect.name == "postgresql"


def rng_choice_in_window(
    rng: random.Random, start: datetime, end: datetime
) -> datetime:
    delta = (end - start).total_seconds()
    offset = rng.uniform(0, delta)
    return start + timedelta(seconds=offset)
