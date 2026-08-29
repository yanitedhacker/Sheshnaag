"""V4 capability policy engine.

Hard capability gates with signed, scoped, time-bound authorization artifacts
and a Merkle-chained append-only audit log.

Every risky action in Sheshnaag V4 calls :meth:`CapabilityPolicy.evaluate`
to decide whether an actor may perform a capability against a given scope.
When permitted the evaluation emits an ``exercise`` audit entry; when denied
it emits a ``deny`` entry. Issuing an artifact requires either single or dual
reviewer sign-off and records an ``issue`` entry plus one ``approve`` entry
per reviewer. Revocation emits a ``revoke`` entry. The chain never mutates:
``entry_hash[i] = sha256(previous_hash[i] || canonical_body[i])`` and each
new row chains on the previous row's ``entry_hash``.

Signing is pluggable through the :class:`Signer` protocol. A production
deployment wires :class:`CosignSigner` (Sigstore keyless / cosign); dev and
test wire :class:`HmacDevSigner` (HMAC-SHA256 with a locally-held key — only
acceptable because the chain itself detects tampering).

The file is intentionally dependency-light: it imports no FastAPI or
request-level state. Callers inject a SQLAlchemy :class:`~sqlalchemy.orm.Session`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.capability import (
    AuditLogEntry,
    AuthorizationArtifact,
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
)
from app.models.malware_lab import ScopePolicy

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "v4.1"
GENESIS_HASH = b"\x00" * 32
_DEFAULT_TTL = timedelta(days=30)
_REQUEST_REVIEW_TTL = timedelta(hours=24)
EXACT_ACTION_CAPABILITIES = frozenset({"autonomous_agent_run"})


# ---------------------------------------------------------------------------
# Capability taxonomy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Capability:
    """A named risky action declared by the capability taxonomy.

    ``requester_roles`` (V5+) names the V5 roles permitted to *originate*
    an issuance request for this capability. ``None`` means "any
    authenticated caller may request" — the V4 default behavior. A
    populated set means the issuance flow will reject requesters whose
    roles do not intersect this set. The V5 W0c slice ships this as
    pure data; the runtime gate is wired in V6 when the
    AuthorizationCenter UI flow lands. The helper
    :meth:`CapabilityPolicy.permitted_requester_for` is provided now so
    callers can adopt voluntarily.
    """

    name: str
    default: str  # "off" | "admin_per_tenant" | "tenant_default"
    review_kind: str  # "single" | "dual" | "dual_plus_admin"
    max_ttl: timedelta
    requires_engagement_doc: bool = False
    requester_roles: Optional[frozenset[str]] = None


# V5 role-tier shortcuts. lab_lead is implicit in both tiers as the
# canonical superuser; explicit listing keeps the kill-criteria red-team
# test honest (no silent superuser bypass — it's spelled out).
_SENIOR_PLUS = frozenset({"senior_analyst", "lab_lead"})
_ANALYST_PLUS = frozenset({"analyst", "senior_analyst", "lab_lead"})


def _cap(
    name: str,
    default: str,
    review_kind: str,
    max_ttl: timedelta,
    *,
    requires_engagement_doc: bool = False,
    requester_roles: Optional[frozenset[str]] = None,
) -> tuple[str, Capability]:
    return name, Capability(
        name=name,
        default=default,
        review_kind=review_kind,
        max_ttl=max_ttl,
        requires_engagement_doc=requires_engagement_doc,
        requester_roles=requester_roles,
    )


# Frozen registry. Adding a capability is a code change + migration, never an
# env override. Keys must match the strings named in the architecture and
# capability-policy specifications.
CAPABILITIES: dict[str, Capability] = dict(
    [
        _cap(
            "dynamic_detonation",
            "admin_per_tenant",
            "single",
            timedelta(days=30),
            requester_roles=_ANALYST_PLUS,
        ),
        _cap(
            "external_disclosure",
            "off",
            "dual_plus_admin",
            timedelta(hours=72),
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "specimen_exfil",
            "off",
            "dual_plus_admin",
            timedelta(days=30),
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "destructive_defang",
            "off",
            "dual",
            timedelta(days=30),
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "cloud_ai_provider_use",
            "tenant_default",
            "single",
            timedelta(days=30),
            requester_roles=_ANALYST_PLUS,
        ),
        _cap(
            "autonomous_agent_run",
            "off",
            "single",
            timedelta(days=30),
            requester_roles=_ANALYST_PLUS,
        ),
        _cap(
            "exploit_validation",
            "off",
            "dual",
            timedelta(days=14),
            requester_roles=_ANALYST_PLUS,
        ),
        _cap(
            "red_team_emulation",
            "off",
            "dual",
            timedelta(days=14),
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "offensive_research",
            "off",
            "dual_plus_admin",
            timedelta(days=7),
            requires_engagement_doc=True,
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "network_egress_open",
            "off",
            "dual_plus_admin",
            timedelta(hours=24),
            requester_roles=_SENIOR_PLUS,
        ),
        _cap(
            "memory_exfil_to_host",
            "admin_per_tenant",
            "single",
            timedelta(days=30),
            requester_roles=_ANALYST_PLUS,
        ),
        _cap(
            "kernel_driver_load",
            "off",
            "dual",
            timedelta(days=14),
            requires_engagement_doc=True,
            requester_roles=_SENIOR_PLUS,
        ),
    ]
)


# ---------------------------------------------------------------------------
# RESERVED_FOR_V7 — capability hooks for the "Output Chain" milestone.
#
# These four names are reserved by the V5-V8 expansion PRD
# (docs/superpowers/specs/2026-05-07-sheshnaag-expansion-design.md, V7).
# They are NOT live entries: adding them to CAPABILITIES now would surface
# UI elements in the AuthorizationCenter that gate nothing, which
# operators and auditors find confusing. V7 kickoff plugs them in here
# with their actual `default` / `review_kind` / `max_ttl` /
# `requester_roles` settings.
#
#   cve_coordination     — CVE/CNA disclosure workflow gate
#   vendor_disclosure    — vendor-coordinated embargo + bundle export gate
#   public_intel_publish — MISP/OTX publisher-side + blog publish gate
#   dataset_publish      — Zenodo / academic publication gate
#
# Cross-reference: frontend/src/permissions.ts will hold a matching
# RESERVED_FOR_V7 constant once W2c lands.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Data carriers (dataclasses — external API surface)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The outcome of a capability evaluation."""

    permitted: bool
    reason: str
    artifact_id: Optional[str] = None


@dataclass(frozen=True)
class Reviewer:
    """A reviewer of an issuance request."""

    reviewer: str
    decision: str  # "approve" | "reject"
    signed_at: Optional[datetime] = None


@dataclass
class IssuanceRequest:
    """A request to issue an authorization artifact."""

    capability: str
    scope: dict
    requester: str
    reason: str
    requested_ttl: Optional[timedelta] = None
    engagement_ref: Optional[str] = None  # sha256 or URL for the engagement doc
    is_admin_approved: bool = False  # set to True when an admin co-signs
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    """Result of walking the audit chain and re-verifying every row."""

    ok: bool
    last_verified_idx: int
    first_bad_idx: Optional[int]
    reason: str


@dataclass(frozen=True)
class AuthorizationDecisionResult:
    """Result of one immutable reviewer decision."""

    request: AuthorizationRequestRecord
    artifact: Optional[AuthorizationArtifact]


class AuthorizationWorkflowError(ValueError):
    """Stable error raised for an invalid authorization transition."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


# ---------------------------------------------------------------------------
# Canonical JSON + helpers
# ---------------------------------------------------------------------------


def _default_json(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Not JSON-serializable: {type(value).__name__}")


def canonical_json(body: Any) -> bytes:
    """Return a deterministic UTF-8 JSON encoding with sorted keys.

    Used anywhere a stable hash or signature input is required. Any value
    types outside JSON-native types are collapsed via ``_default_json``.
    """

    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default_json,
    ).encode("utf-8")


def exact_action_digest(action: str, arguments: dict[str, Any]) -> str:
    """Return the SHA-256 digest for one validated action request."""

    body = canonical_json({"action": action, "arguments": arguments})
    return "sha256:" + hashlib.sha256(body).hexdigest()


def exact_action_scope(
    action: str,
    arguments: dict[str, Any],
    *,
    tenant_id: int,
    case_id: Optional[int] = None,
) -> dict[str, Any]:
    """Build the capability scope that binds an artifact to one action."""

    scope: dict[str, Any] = {
        "tenant_id": tenant_id,
        "action": action,
        "action_digest": exact_action_digest(action, arguments),
    }
    if case_id is not None:
        scope["case_id"] = case_id
    return scope


def _valid_exact_action_scope(capability: str, scope: dict[str, Any]) -> bool:
    if scope.get("action") != capability:
        return False
    digest = scope.get("action_digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        return False
    hexadecimal = digest.removeprefix("sha256:")
    return (
        len(hexadecimal) == 64
        and hexadecimal == hexadecimal.lower()
        and all(character in "0123456789abcdef" for character in hexadecimal)
    )


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Signers
# ---------------------------------------------------------------------------


class Signer(Protocol):
    """Signing abstraction the policy calls into."""

    name: str

    def sign(self, body: bytes) -> tuple[bytes, bytes]:
        """Return ``(signature, cert_or_pubkey)`` for ``body``."""

    def verify(self, body: bytes, signature: bytes, cert: bytes) -> bool:
        """Return True iff ``signature`` is valid for ``body`` under ``cert``."""


class ProductionSignerUnavailable(RuntimeError):
    """A secure deployment could not construct its required signer."""


class HmacDevSigner:
    """HMAC-SHA256 signer for development / test.

    The key is loaded from ``AUDIT_SIGNING_KEY`` (hex or raw utf-8) or
    generated at process start if unset. Emits a WARNING on construction so
    deployment rigs can detect that production is falling back to HMAC.
    """

    name = "hmac-sha256"
    _WARNED = False

    def __init__(self, key: Optional[bytes] = None) -> None:
        if key is None:
            raw = os.getenv("AUDIT_SIGNING_KEY", "")
            if raw:
                try:
                    key = bytes.fromhex(raw)
                except ValueError:
                    key = raw.encode("utf-8")
            else:
                key = secrets.token_bytes(32)
        self._key = key
        if not HmacDevSigner._WARNED:
            logger.warning(
                "HmacDevSigner is active: audit-log signatures are HMAC-only "
                "and acceptable for dev/test. Production must wire CosignSigner."
            )
            HmacDevSigner._WARNED = True

    @property
    def cert(self) -> bytes:
        # The "cert" for HMAC is a stable identifier of the key — the SHA-256
        # of the key material. The key itself is never stored on-disk in a row.
        return hashlib.sha256(self._key).digest()

    def sign(self, body: bytes) -> tuple[bytes, bytes]:
        sig = hmac.new(self._key, body, hashlib.sha256).digest()
        return sig, self.cert

    def verify(self, body: bytes, signature: bytes, cert: bytes) -> bool:
        if cert != self.cert:
            return False
        expected = hmac.new(self._key, body, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


class CosignSigner:
    """Sigstore / cosign signer.

    Wraps the ``sigstore`` python package if installed; falls back to
    :class:`HmacDevSigner` otherwise (with a WARNING). The fallback lets
    developers run the full suite without the full Sigstore toolchain while
    still exercising every signature-bearing code path.

    Production deployments enable real Sigstore by setting
    ``SHESHNAAG_AUDIT_SIGNER=cosign`` and installing ``sigstore>=3``. The
    underlying implementation publishes each signature into the public
    Rekor transparency log, giving the audit chain an externally verifiable
    timestamp anchor in addition to the local hash chain.
    """

    name = "cosign-sigstore"

    def __init__(self, *, allow_hmac_fallback: bool = True) -> None:
        try:
            import sigstore  # noqa: F401  # keep optional
            self._impl: Any = _SigstoreImpl()
        except Exception as exc:  # pragma: no cover — optional dep missing in dev
            if not allow_hmac_fallback:
                raise ProductionSignerUnavailable(
                    f"sigstore_unavailable:{exc.__class__.__name__}"
                ) from exc
            logger.warning(
                "CosignSigner requested but sigstore unavailable (%s); "
                "falling back to HmacDevSigner for development only.",
                exc,
            )
            self._impl = HmacDevSigner()

    @property
    def using_sigstore(self) -> bool:
        return not isinstance(self._impl, HmacDevSigner)

    def sign(self, body: bytes) -> tuple[bytes, bytes]:
        return self._impl.sign(body)

    def verify(self, body: bytes, signature: bytes, cert: bytes) -> bool:
        return self._impl.verify(body, signature, cert)


class _SigstoreImpl:  # pragma: no cover — exercised in production; mocked in tests
    """Thin shim over the sigstore client.

    Wiring contract:

    - ``sign(body)`` signs the canonical body with a Fulcio-issued ephemeral
      certificate, publishes the signature to Rekor, and returns
      ``(signature_bytes, cert_pem)``. The Rekor log entry is also persisted
      onto the audit row payload via :class:`CapabilityPolicy` when the
      caller opts in.
    - ``verify(body, signature, cert)`` performs the equivalent reverse
      operation against the Sigstore public-good instance.

    Operators who need an offline Rekor (e.g. air-gapped beta hosts) should
    set ``SIGSTORE_REKOR_URL`` and ``SIGSTORE_FULCIO_URL`` to the relevant
    private endpoints; the underlying ``sigstore`` library reads these.
    """

    def __init__(self) -> None:
        from sigstore.sign import SigningContext

        self._ctx = SigningContext.production()
        self._last_rekor_log_index: Optional[int] = None
        self._last_rekor_log_id: Optional[str] = None

    def sign(self, body: bytes) -> tuple[bytes, bytes]:
        import io

        with self._ctx.signer() as signer:
            bundle = signer.sign_artifact(io.BytesIO(body))
        sig = bundle.signature
        cert = bundle.signing_certificate.public_bytes(
            encoding=getattr(
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]),
                "Encoding",
            ).PEM
        )
        # Persist the most recent Rekor coordinates so callers can stash
        # them onto the audit-row payload without re-issuing a network call.
        rekor_entry = getattr(bundle, "log_entry", None)
        if rekor_entry is not None:
            self._last_rekor_log_index = getattr(rekor_entry, "log_index", None)
            self._last_rekor_log_id = getattr(rekor_entry, "log_id", None)
        return sig, cert

    def verify(self, body: bytes, signature: bytes, cert: bytes) -> bool:
        from sigstore.verify import Verifier

        verifier = Verifier.production()
        try:
            verifier.verify(body, signature, cert)
            return True
        except Exception:
            return False

    @property
    def last_rekor(self) -> dict:
        return {
            "log_index": self._last_rekor_log_index,
            "log_id": self._last_rekor_log_id,
        }


def build_signer() -> Signer:
    """Pick a signer based on the ``SHESHNAAG_AUDIT_SIGNER`` env var."""

    choice = os.getenv("SHESHNAAG_AUDIT_SIGNER", "hmac").strip().lower()
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    deployment_profile = os.getenv(
        "DEPLOYMENT_PROFILE", "local_dev"
    ).strip().lower()
    secure_profiles = {
        "design_partner_beta",
        "full_v4_beta",
        "release_verification",
    }
    secure_runtime = environment in {"staging", "production"} or (
        deployment_profile in secure_profiles
    )
    if secure_runtime and choice != "cosign":
        raise ProductionSignerUnavailable("cosign_required_for_secure_runtime")
    if choice == "cosign":
        return CosignSigner(allow_hmac_fallback=not secure_runtime)
    if choice == "hmac":
        return HmacDevSigner()
    raise ValueError(f"unknown_audit_signer:{choice}")


# ---------------------------------------------------------------------------
# CapabilityPolicy
# ---------------------------------------------------------------------------


class CapabilityPolicy:
    """Evaluate, issue, and revoke capability authorizations."""

    def __init__(self, session: Session, *, signer: Optional[Signer] = None) -> None:
        self._session = session
        self._signer: Signer = signer or build_signer()

    # ---- public API -------------------------------------------------------

    @staticmethod
    def permitted_requester_for(
        capability: str, roles: Iterable[str]
    ) -> bool:
        """Return True if any of ``roles`` may originate an issuance request.

        V5 W0c data hook. Used by V6 AuthorizationCenter to gate the
        "Request capability" form: the request button is disabled when
        this returns False.

        Returns ``True`` for any capability whose ``requester_roles`` is
        ``None`` (V4 default — anyone authenticated may request) and for
        any capability where one of the caller's roles is in the
        ``requester_roles`` set.

        Returns ``False`` for an unknown capability — fail-closed so an
        operator does not accidentally allow a typo'd capability.
        """

        cap = CAPABILITIES.get(capability)
        if cap is None:
            return False
        if cap.requester_roles is None:
            return True
        return bool(set(roles) & cap.requester_roles)

    def create_request(
        self,
        *,
        capability: str,
        action: str,
        arguments: dict[str, Any],
        requester: str,
        reason: str,
        requested_ttl: Optional[timedelta] = None,
        engagement_ref: Optional[str] = None,
    ) -> AuthorizationRequestRecord:
        """Create a pending request for one server-derived exact action."""

        cap = CAPABILITIES.get(capability)
        if cap is None:
            raise AuthorizationWorkflowError(f"unknown_capability:{capability}")
        if action != capability:
            raise AuthorizationWorkflowError("action_must_match_capability")
        if not isinstance(arguments, dict):
            raise AuthorizationWorkflowError("action_arguments_must_be_object")
        tenant_id = arguments.get("tenant_id")
        if isinstance(tenant_id, bool) or not isinstance(tenant_id, int):
            raise AuthorizationWorkflowError("tenant_id_required")
        if cap.requires_engagement_doc and not engagement_ref:
            raise AuthorizationWorkflowError("need_engagement_doc")

        ttl = requested_ttl or cap.max_ttl
        if ttl <= timedelta(0):
            raise AuthorizationWorkflowError("requested_ttl_must_be_positive")
        ttl = min(ttl, cap.max_ttl)
        now = utc_now()
        case_id = arguments.get("case_id")
        if isinstance(case_id, bool) or (
            case_id is not None and not isinstance(case_id, int)
        ):
            raise AuthorizationWorkflowError("case_id_must_be_integer")
        scope = exact_action_scope(
            action,
            arguments,
            tenant_id=tenant_id,
            case_id=case_id,
        )
        required_approvals = 1 if cap.review_kind == "single" else 2
        row = AuthorizationRequestRecord(
            request_id="areq_" + uuid.uuid4().hex[:24],
            capability=capability,
            scope=scope,
            action=action,
            action_digest=scope["action_digest"],
            requester=requester,
            reason=reason,
            requested_ttl_seconds=int(ttl.total_seconds()),
            engagement_ref=engagement_ref,
            status="pending",
            required_approvals=required_approvals,
            requires_admin_approval=cap.review_kind == "dual_plus_admin",
            created_at=now,
            expires_at=now + min(ttl, _REQUEST_REVIEW_TTL),
        )
        self._session.add(row)
        self._session.flush()
        self._append_audit_entry(
            action="request",
            actor=requester,
            capability=capability,
            artifact_id=None,
            scope=scope,
            payload={
                "request_id": row.request_id,
                "reason": reason,
                "requested_ttl_seconds": row.requested_ttl_seconds,
                "review_expires_at": row.expires_at.isoformat().replace(
                    "+00:00", "Z"
                ),
            },
        )
        return row

    def record_decision(
        self,
        request_id: str,
        *,
        reviewer: str,
        reviewer_roles: Iterable[str],
        decision: str,
        note: Optional[str],
    ) -> AuthorizationDecisionResult:
        """Record one reviewer decision and issue when the threshold is met."""

        normalized_decision = decision.strip().lower()
        if normalized_decision not in {"approve", "reject"}:
            raise AuthorizationWorkflowError("invalid_decision")
        request_row = self._session.get(AuthorizationRequestRecord, request_id)
        if request_row is None:
            raise AuthorizationWorkflowError(f"unknown_request:{request_id}")
        if request_row.status != "pending":
            raise AuthorizationWorkflowError(
                f"request_not_pending:{request_row.status}"
            )
        if _ensure_aware(request_row.expires_at) <= _ensure_aware(utc_now()):
            raise AuthorizationWorkflowError("request_expired")
        if reviewer == request_row.requester:
            raise AuthorizationWorkflowError("requester_cannot_review")
        duplicate = self._session.execute(
            select(AuthorizationDecisionRecord)
            .where(AuthorizationDecisionRecord.request_id == request_id)
            .where(AuthorizationDecisionRecord.reviewer == reviewer)
        ).scalars().first()
        if duplicate is not None:
            raise AuthorizationWorkflowError("duplicate_reviewer_decision")

        roles = sorted({str(role) for role in reviewer_roles if str(role)})
        decision_row = AuthorizationDecisionRecord(
            request_id=request_id,
            reviewer=reviewer,
            reviewer_roles=roles,
            decision=normalized_decision,
            note=note,
        )
        self._session.add(decision_row)
        self._session.flush()
        self._append_audit_entry(
            action=normalized_decision,
            actor=reviewer,
            capability=request_row.capability,
            artifact_id=None,
            scope=request_row.scope or {},
            payload={
                "request_id": request_id,
                "note": note,
                "reviewer_roles": roles,
            },
        )

        if normalized_decision == "reject":
            request_row.status = "rejected"
            request_row.resolved_at = utc_now()
            self._session.flush()
            return AuthorizationDecisionResult(request_row, None)

        approvals = self._session.execute(
            select(AuthorizationDecisionRecord)
            .where(AuthorizationDecisionRecord.request_id == request_id)
            .where(AuthorizationDecisionRecord.decision == "approve")
            .order_by(AuthorizationDecisionRecord.id.asc())
        ).scalars().all()
        enough_approvals = len(approvals) >= request_row.required_approvals
        has_admin_approval = any(
            "lab_lead" in set(row.reviewer_roles or []) for row in approvals
        )
        if not enough_approvals or (
            request_row.requires_admin_approval and not has_admin_approval
        ):
            return AuthorizationDecisionResult(request_row, None)

        reviewers = [
            Reviewer(
                reviewer=row.reviewer,
                decision="approve",
                signed_at=row.created_at,
            )
            for row in approvals
        ]
        issuance = IssuanceRequest(
            capability=request_row.capability,
            scope=request_row.scope or {},
            requester=request_row.requester,
            reason=request_row.reason,
            requested_ttl=timedelta(
                seconds=request_row.requested_ttl_seconds
            )
            if request_row.requested_ttl_seconds is not None
            else None,
            engagement_ref=request_row.engagement_ref,
            is_admin_approved=has_admin_approval,
            extra={
                "request_id": request_id,
                "action": request_row.action,
                "action_digest": request_row.action_digest,
            },
        )
        artifact = self._issue_artifact(
            issuance,
            reviewers,
            audit_approvals=False,
        )
        request_row.status = "issued"
        request_row.artifact_id = artifact.artifact_id
        request_row.resolved_at = utc_now()
        self._session.flush()
        return AuthorizationDecisionResult(request_row, artifact)

    def evaluate(self, *, capability: str, scope: dict, actor: str) -> Decision:
        """Resolve ``(capability, scope, actor)`` against the active artifacts."""

        cap = CAPABILITIES.get(capability)
        if cap is None:
            decision = Decision(False, f"unknown_capability:{capability}", None)
            self._append_audit_entry(
                action="deny",
                actor=actor,
                capability=capability,
                artifact_id=None,
                scope=scope,
                payload={"reason": decision.reason},
            )
            return decision

        if capability in EXACT_ACTION_CAPABILITIES and not _valid_exact_action_scope(
            capability, scope
        ):
            decision = Decision(False, "exact_action_scope_required", None)
            self._append_audit_entry(
                action="deny",
                actor=actor,
                capability=capability,
                artifact_id=None,
                scope=scope,
                payload={"reason": decision.reason},
            )
            return decision

        # Tenant-default fast path: if the tenant's ScopePolicy declares this
        # capability as pre-authorized, permit without an artifact.
        if capability not in EXACT_ACTION_CAPABILITIES and self._tenant_permits(
            capability, scope
        ):
            decision = Decision(True, "tenant_default", None)
            self._append_audit_entry(
                action="exercise",
                actor=actor,
                capability=capability,
                artifact_id=None,
                scope=scope,
                payload={"reason": "tenant_default"},
            )
            return decision

        artifact = self._find_active_artifact(capability, scope)
        if artifact is None:
            reason = (
                "no_matching_exact_action_artifact"
                if capability in EXACT_ACTION_CAPABILITIES
                else "no_active_artifact"
            )
            decision = Decision(False, reason, None)
            self._append_audit_entry(
                action="deny",
                actor=actor,
                capability=capability,
                artifact_id=None,
                scope=scope,
                payload={"reason": decision.reason},
            )
            return decision

        decision = Decision(True, "artifact_match", artifact.artifact_id)
        self._append_audit_entry(
            action="exercise",
            actor=actor,
            capability=capability,
            artifact_id=artifact.artifact_id,
            scope=scope,
            payload={"reason": "artifact_match"},
        )
        return decision

    def issue(
        self,
        request: IssuanceRequest,
        reviewers: list[Reviewer],
    ) -> AuthorizationArtifact:
        """Validate and persist an authorization artifact."""

        return self._issue_artifact(request, reviewers, audit_approvals=True)

    def _issue_artifact(
        self,
        request: IssuanceRequest,
        reviewers: list[Reviewer],
        *,
        audit_approvals: bool,
    ) -> AuthorizationArtifact:
        """Issue an artifact from validated reviewer records."""

        cap = CAPABILITIES.get(request.capability)
        if cap is None:
            raise ValueError(f"unknown_capability:{request.capability}")

        approving = [r for r in reviewers if r.decision == "approve"]
        names = {r.reviewer for r in approving}

        if request.requester in names:
            raise ValueError("requester_cannot_review")

        if len(names) != len(approving):
            raise ValueError("duplicate_reviewer")

        required = 1 if cap.review_kind == "single" else 2
        if len(approving) < required:
            raise ValueError(
                f"need_{required}_approvals_got_{len(approving)}"
            )

        if cap.review_kind == "dual_plus_admin" and not request.is_admin_approved:
            raise ValueError("need_admin_approval")

        if cap.requires_engagement_doc and not request.engagement_ref:
            raise ValueError("need_engagement_doc")

        # Clamp TTL to the capability's max. Requesters may shorten but never
        # extend the default window.
        ttl = request.requested_ttl or cap.max_ttl
        if ttl > cap.max_ttl:
            ttl = cap.max_ttl

        issued_at = utc_now()
        expires_at = issued_at + ttl

        artifact_id = self._new_artifact_id()
        nonce = secrets.token_hex(16)

        previous_root = self._latest_entry_hash()

        reviewers_payload = [
            {
                "reviewer": r.reviewer,
                "decision": r.decision,
                "signed_at": _ensure_aware(r.signed_at or issued_at).isoformat().replace(
                    "+00:00", "Z"
                ),
            }
            for r in approving
        ]
        requester_payload = {
            "analyst": request.requester,
            "reason": request.reason,
        }
        if request.engagement_ref:
            requester_payload["engagement_ref"] = request.engagement_ref
        if request.extra:
            requester_payload.update(request.extra)

        body = {
            "artifact_id": artifact_id,
            "schema_version": SCHEMA_VERSION,
            "capability": cap.name,
            "scope": request.scope,
            "requester": requester_payload,
            "reviewers": reviewers_payload,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "nonce": nonce,
            "previous_audit_hash": base64.b64encode(previous_root).decode("ascii"),
        }
        body_bytes = canonical_json(body)
        signature, cert = self._signer.sign(body_bytes)

        artifact = AuthorizationArtifact(
            artifact_id=artifact_id,
            schema_version=SCHEMA_VERSION,
            capability=cap.name,
            scope=request.scope,
            requester=requester_payload,
            reviewers=reviewers_payload,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            previous_audit_hash=previous_root,
            signer_cert=cert,
            signature=signature,
        )
        self._session.add(artifact)
        self._session.flush()

        # The artifact's signature/cert go on the artifact row. The audit
        # entry signs its OWN body independently so verify_chain() can check
        # each row's signature against that row's canonical body.
        self._append_audit_entry(
            action="issue",
            actor=request.requester,
            capability=cap.name,
            artifact_id=artifact_id,
            scope=request.scope,
            payload={
                "reason": request.reason,
                "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                "ttl_seconds": ttl.total_seconds(),
                "engagement_ref": request.engagement_ref,
            },
        )
        if audit_approvals:
            for reviewer in approving:
                self._append_audit_entry(
                    action="approve",
                    actor=reviewer.reviewer,
                    capability=cap.name,
                    artifact_id=artifact_id,
                    scope=request.scope,
                    payload={
                        "signed_at": _ensure_aware(reviewer.signed_at or issued_at)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    },
                )

        return artifact

    def revoke(self, artifact_id: str, actor: str, reason: str) -> None:
        artifact = self._session.get(AuthorizationArtifact, artifact_id)
        if artifact is None:
            raise ValueError(f"unknown_artifact:{artifact_id}")
        if artifact.revoked_at is not None:
            raise ValueError("already_revoked")
        artifact.revoked_at = utc_now()
        artifact.revoked_by = actor
        artifact.revoke_reason = reason
        self._session.flush()

        self._append_audit_entry(
            action="revoke",
            actor=actor,
            capability=artifact.capability,
            artifact_id=artifact_id,
            scope=artifact.scope or {},
            payload={"reason": reason},
        )

    def latest_root(self) -> dict:
        row = self._session.execute(
            select(AuditLogEntry).order_by(AuditLogEntry.idx.desc()).limit(1)
        ).scalars().first()
        if row is None:
            return {"idx": -1, "entry_hash": base64.b64encode(GENESIS_HASH).decode("ascii")}
        return {
            "idx": int(row.idx),
            "entry_hash": base64.b64encode(bytes(row.entry_hash)).decode("ascii"),
        }

    def verify_chain(self, since: Optional[int] = None) -> VerificationResult:
        query = select(AuditLogEntry).order_by(AuditLogEntry.idx.asc())
        if since is not None:
            query = query.where(AuditLogEntry.idx >= since)

        previous_hash = GENESIS_HASH
        last_verified_idx = -1

        if since is not None and since > 0:
            prior = self._session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.idx < since)
                .order_by(AuditLogEntry.idx.desc())
                .limit(1)
            ).scalars().first()
            if prior is not None:
                previous_hash = bytes(prior.entry_hash)
                last_verified_idx = int(prior.idx)

        rows: Iterable[AuditLogEntry] = self._session.execute(query).scalars()
        for row in rows:
            if bytes(row.previous_hash) != previous_hash:
                return VerificationResult(
                    ok=False,
                    last_verified_idx=last_verified_idx,
                    first_bad_idx=int(row.idx),
                    reason="previous_hash_mismatch",
                )

            body_bytes = canonical_json(self._audit_body(row))
            expected = _sha256(previous_hash + body_bytes)
            if bytes(row.entry_hash) != expected:
                return VerificationResult(
                    ok=False,
                    last_verified_idx=last_verified_idx,
                    first_bad_idx=int(row.idx),
                    reason="entry_hash_mismatch",
                )

            if row.signature is not None and row.signer_cert is not None:
                if not self._signer.verify(
                    body_bytes, bytes(row.signature), bytes(row.signer_cert)
                ):
                    return VerificationResult(
                        ok=False,
                        last_verified_idx=last_verified_idx,
                        first_bad_idx=int(row.idx),
                        reason="signature_invalid",
                    )

            previous_hash = bytes(row.entry_hash)
            last_verified_idx = int(row.idx)

        return VerificationResult(
            ok=True,
            last_verified_idx=last_verified_idx,
            first_bad_idx=None,
            reason="ok",
        )

    # ---- internals --------------------------------------------------------

    def _new_artifact_id(self) -> str:
        return "auth_" + uuid.uuid4().hex[:24]

    def _latest_entry_hash(self) -> bytes:
        row = self._session.execute(
            select(AuditLogEntry).order_by(AuditLogEntry.idx.desc()).limit(1)
        ).scalars().first()
        if row is None:
            return GENESIS_HASH
        return bytes(row.entry_hash)

    def _audit_body(self, row: AuditLogEntry) -> dict:
        """Canonicalizable body for an audit entry's hash.

        Excludes ``entry_hash``, ``signature``, and ``signer_cert`` — those
        cover the body, so they cannot be inputs to themselves.
        """

        return {
            "idx": int(row.idx),
            "previous_hash": base64.b64encode(bytes(row.previous_hash)).decode("ascii"),
            "actor": row.actor,
            "action": row.action,
            "capability": row.capability,
            "artifact_id": row.artifact_id,
            "scope": row.scope or {},
            "payload": row.payload or {},
            "signed_at": _ensure_aware(row.signed_at)
            .isoformat()
            .replace("+00:00", "Z"),
        }

    def _append_audit_entry(
        self,
        *,
        action: str,
        actor: str,
        capability: str,
        artifact_id: Optional[str],
        scope: dict,
        payload: dict,
        signer_cert: Optional[bytes] = None,
        signature: Optional[bytes] = None,
    ) -> AuditLogEntry:
        previous_hash = self._latest_entry_hash()
        signed_at = utc_now()

        # Reserve the idx first so the hash commits to it. Flushing a row with
        # a placeholder hash would require an UPDATE, which the append-only
        # trigger blocks; instead we compute the next idx by asking the DB for
        # the current max and incrementing.
        last = self._session.execute(
            select(AuditLogEntry.idx).order_by(AuditLogEntry.idx.desc()).limit(1)
        ).scalar()
        next_idx = 0 if last is None else int(last) + 1

        body = {
            "idx": next_idx,
            "previous_hash": base64.b64encode(previous_hash).decode("ascii"),
            "actor": actor,
            "action": action,
            "capability": capability,
            "artifact_id": artifact_id,
            "scope": scope or {},
            "payload": payload or {},
            "signed_at": signed_at.isoformat().replace("+00:00", "Z"),
        }
        body_bytes = canonical_json(body)
        entry_hash = _sha256(previous_hash + body_bytes)

        if signature is None or signer_cert is None:
            signature, signer_cert = self._signer.sign(body_bytes)

        row = AuditLogEntry(
            idx=next_idx,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            actor=actor,
            action=action,
            capability=capability,
            artifact_id=artifact_id,
            scope=scope or {},
            payload=payload or {},
            signed_at=signed_at,
            signer_cert=signer_cert,
            signature=signature,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def _tenant_permits(self, capability: str, scope: dict) -> bool:
        tenant_id = scope.get("tenant_id") if isinstance(scope, dict) else None
        if tenant_id is None:
            return False
        # Schema-tolerance: the capability-policy engine runs in environments
        # that may not have the full domain schema (unit tests install only
        # the capability-policy tables). We try the query and treat an
        # "unknown table" OperationalError as "capability not tenant-default".
        # Using inspect() on the bind would open a sibling DBAPI connection,
        # which on in-memory SQLite + StaticPool resets the in-flight
        # transaction and wipes uncommitted rows — so avoid it.
        # Wrap the potentially-failing query in a SAVEPOINT so a missing
        # ``scope_policies`` table does not taint the outer transaction that
        # may already carry uncommitted artifact / audit rows.
        try:
            with self._session.begin_nested():
                policy = self._session.execute(
                    select(ScopePolicy)
                    .where(ScopePolicy.tenant_id == tenant_id)
                    .where(ScopePolicy.status == "active")
                ).scalars().first()
        except Exception:
            return False
        if policy is None:
            return False
        doc = policy.policy or {}
        defaults = doc.get("tenant_default_capabilities") or []
        return capability in set(defaults)

    def _find_active_artifact(
        self, capability: str, scope: dict
    ) -> Optional[AuthorizationArtifact]:
        now = utc_now()
        rows = self._session.execute(
            select(AuthorizationArtifact)
            .where(AuthorizationArtifact.capability == capability)
            .where(AuthorizationArtifact.revoked_at.is_(None))
            .where(AuthorizationArtifact.expires_at > now)
            .order_by(AuthorizationArtifact.issued_at.desc())
        ).scalars().all()
        for row in rows:
            if capability in EXACT_ACTION_CAPABILITIES:
                artifact_scope = row.scope or {}
                if not _valid_exact_action_scope(capability, artifact_scope):
                    continue
                if artifact_scope.get("action") != scope.get("action"):
                    continue
                if artifact_scope.get("action_digest") != scope.get(
                    "action_digest"
                ):
                    continue
            if self._scope_matches(row.scope or {}, scope or {}):
                return row
        return None

    @staticmethod
    def _scope_matches(artifact_scope: dict, request_scope: dict) -> bool:
        """Request scope must be contained by artifact scope.

        Rules:
          - A key missing from the artifact means "unconstrained on that key".
          - A key present in the artifact with a list constrains the request
            to members of that list. If the request omits the key, deny.
          - A key present in the artifact with a scalar requires equality.
          - ``max_runs`` / ``max_*`` numeric caps are informational here (the
            caller enforces them); we simply require the request not exceed.
        """

        for key, cap_value in artifact_scope.items():
            req_value = request_scope.get(key)
            if key.startswith("max_"):
                if req_value is None:
                    continue
                try:
                    if float(req_value) > float(cap_value):
                        return False
                except (TypeError, ValueError):
                    return False
                continue
            if isinstance(cap_value, list):
                if req_value is None:
                    return False
                if isinstance(req_value, list):
                    if not set(req_value).issubset(set(cap_value)):
                        return False
                elif req_value not in cap_value:
                    return False
            else:
                if req_value != cap_value:
                    return False
        return True


__all__ = [
    "AuthorizationDecisionResult",
    "AuthorizationWorkflowError",
    "CAPABILITIES",
    "EXACT_ACTION_CAPABILITIES",
    "Capability",
    "CapabilityPolicy",
    "CosignSigner",
    "Decision",
    "GENESIS_HASH",
    "HmacDevSigner",
    "IssuanceRequest",
    "Reviewer",
    "ProductionSignerUnavailable",
    "SCHEMA_VERSION",
    "Signer",
    "VerificationResult",
    "build_signer",
    "canonical_json",
    "exact_action_digest",
    "exact_action_scope",
]
