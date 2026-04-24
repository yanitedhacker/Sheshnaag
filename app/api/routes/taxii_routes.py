"""TAXII 2.1 server for Sheshnaag V4 partner sharing.

Implements the server side of the TAXII 2.1 specification:

    https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html

The server exposes:

  * ``GET  /taxii2/`` — server-discovery document.
  * ``GET  /taxii2/api1/`` — API-root metadata.
  * ``GET  /taxii2/api1/collections`` — list collections.
  * ``GET  /taxii2/api1/collections/{collection_id}`` — single collection.
  * ``GET  /taxii2/api1/collections/{collection_id}/objects`` — STIX
    bundle of the collection's objects (supports pagination via HTTP
    ``Range: items=START-END``).
  * ``GET  /taxii2/api1/collections/{collection_id}/objects/{object_id}``
    — a single STIX object as a bundle envelope.
  * ``POST /taxii2/api1/collections/{collection_id}/objects`` — ingest a
    STIX bundle; validates it before persisting and returns a TAXII
    Status object.
  * ``GET  /taxii2/api1/collections/{collection_id}/manifest`` — the
    per-object manifest with media-type + version info.

Every route is gated by ``require_capability("external_disclosure")`` —
TAXII publishing is a cross-tenant disclosure and needs the V4 capability
artifact before any byte leaves the building.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import require_capability
from app.core.time import utc_now
from app.models.malware_lab import AnalysisCase
from app.models.v2 import Tenant
from app.services.stix_exporter import StixExporter

logger = logging.getLogger(__name__)

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
TAXII_SPEC_VERSION = "2.1"

router = APIRouter(prefix="/taxii2", tags=["Sheshnaag V4 TAXII 2.1"])

# In-process ephemeral store for POST-ingested bundles. A production
# deployment would persist these into the domain model; for Slice 3 of V4
# we hold the objects in memory so the server round-trips correctly and
# operators can validate the wire shape end-to-end. The key is the
# collection_id, the value is a dict keyed by STIX object id.
_INGEST_STORE: Dict[str, Dict[str, Dict[str, Any]]] = {}

# In-process Status registry for POST operations so clients can follow up.
_STATUS_STORE: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _taxii_json(body: Any, *, status_code: int = 200, extra_headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    """Return a JSONResponse with the TAXII 2.1 media-type."""

    headers = {"Content-Type": TAXII_CONTENT_TYPE}
    if extra_headers:
        headers.update(extra_headers)
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type=TAXII_CONTENT_TYPE,
        headers=headers,
    )


def _utc_z(value: Optional[datetime] = None) -> str:
    if value is None:
        value = utc_now()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    iso = value.astimezone(timezone.utc).isoformat()
    if iso.endswith("+00:00"):
        return iso[:-6] + "Z"
    if not iso.endswith("Z"):
        return iso + "Z"
    return iso


def _parse_collection_id(collection_id: str) -> Tuple[Optional[int], Optional[str]]:
    """Parse ``tenant-<id>--<label>`` collection ids.

    Collections in Sheshnaag V4 are deterministic per ``(tenant_id, label)``
    pairs: ``tenant-42--indicators``. We allow alphanumeric labels, dashes,
    and underscores.
    """

    match = re.match(r"^tenant-(\d+)--([a-z0-9_\-]+)$", collection_id)
    if not match:
        return None, None
    return int(match.group(1)), match.group(2)


_COLLECTION_LABELS = ("indicators", "malware", "reports", "all")


def _resolve_tenants(session: Session) -> List[Tenant]:
    return session.query(Tenant).filter(Tenant.is_active.is_(True)).all()


def _build_collection(tenant: Tenant, label: str) -> Dict[str, Any]:
    slug = tenant.slug or f"tenant-{tenant.id}"
    collection_id = f"tenant-{tenant.id}--{label}"
    return {
        "id": collection_id,
        "title": f"{slug} — {label}",
        "description": (
            f"STIX 2.1 {label} objects scoped to tenant {slug} "
            f"(tenant_id={tenant.id})."
        ),
        "can_read": True,
        "can_write": True,
        "media_types": [TAXII_CONTENT_TYPE, "application/stix+json;version=2.1"],
    }


def _list_collections(session: Session) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for tenant in _resolve_tenants(session):
        for label in _COLLECTION_LABELS:
            out.append(_build_collection(tenant, label))
    return out


def _find_collection(session: Session, collection_id: str) -> Optional[Dict[str, Any]]:
    tenant_id, label = _parse_collection_id(collection_id)
    if tenant_id is None or label is None or label not in _COLLECTION_LABELS:
        return None
    tenant = session.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        return None
    return _build_collection(tenant, label)


def _tenant_for_collection(session: Session, collection_id: str) -> Tuple[Optional[Tenant], Optional[str]]:
    tenant_id, label = _parse_collection_id(collection_id)
    if tenant_id is None:
        return None, None
    tenant = session.query(Tenant).filter(Tenant.id == tenant_id).first()
    return tenant, label


def _collect_tenant_objects(session: Session, tenant: Tenant, label: str) -> List[Dict[str, Any]]:
    """Materialize STIX objects for the given ``(tenant, label)`` collection.

    We iterate every analysis case for the tenant, export its bundle, and
    concatenate the SDOs, filtering by label where applicable. Objects
    POSTed via the ingest endpoint are appended last so they show up in
    listing and fetch-by-id.
    """

    exporter = StixExporter(session)
    seen_ids: set[str] = set()
    aggregated: List[Dict[str, Any]] = []

    cases = (
        session.query(AnalysisCase)
        .filter(AnalysisCase.tenant_id == tenant.id)
        .order_by(AnalysisCase.id.asc())
        .all()
    )
    for case in cases:
        try:
            bundle = exporter.export_case(tenant, case.id)
        except Exception:  # pragma: no cover — defensive
            logger.warning(
                "TAXII collection export failed for tenant=%s case=%s",
                tenant.id, case.id, exc_info=True,
            )
            continue
        for obj in bundle.get("objects", []):
            if not isinstance(obj, dict):
                continue
            otype = obj.get("type")
            if label != "all":
                if label == "indicators" and otype != "indicator":
                    continue
                if label == "malware" and otype != "malware":
                    continue
                if label == "reports" and otype != "report":
                    continue
            if obj.get("id") in seen_ids:
                continue
            seen_ids.add(obj.get("id"))
            aggregated.append(obj)

    # Append ingested bundles, filtered the same way.
    collection_id = f"tenant-{tenant.id}--{label}"
    for ingested in _INGEST_STORE.get(collection_id, {}).values():
        if ingested.get("id") in seen_ids:
            continue
        seen_ids.add(ingested.get("id"))
        aggregated.append(ingested)

    return aggregated


def _parse_range(range_header: Optional[str]) -> Tuple[int, Optional[int]]:
    """Parse a ``Range: items=start-end`` header.

    Returns ``(start, end_inclusive)`` where ``end_inclusive`` is ``None``
    when omitted. Defaults to ``(0, None)`` if the header is absent.
    """

    if not range_header:
        return 0, None
    m = re.match(r"^\s*items\s*=\s*(\d+)\s*-\s*(\d*)\s*$", range_header)
    if not m:
        return 0, None
    start = int(m.group(1))
    end_raw = m.group(2)
    end = int(end_raw) if end_raw else None
    return start, end


def _make_envelope(
    objects: List[Dict[str, Any]],
    *,
    start: int,
    total: int,
) -> Dict[str, Any]:
    envelope: Dict[str, Any] = {"objects": objects}
    if not objects:
        envelope["more"] = False
        return envelope
    envelope["more"] = (start + len(objects)) < total
    envelope["next"] = str(start + len(objects)) if envelope["more"] else None
    return envelope


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def discovery():
    """TAXII 2.1 discovery document — lists the API roots this server serves."""

    body = {
        "title": "Sheshnaag V4 TAXII Server",
        "description": (
            "Sheshnaag V4 Threat Intel Fabric — partner TAXII 2.1 endpoint. "
            "Every exchange is gated by the V4 `external_disclosure` capability."
        ),
        "contact": "security@sheshnaag.invalid",
        "default": "/taxii2/api1/",
        "api_roots": ["/taxii2/api1/"],
    }
    return _taxii_json(body)


@router.get(
    "/api1/",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def api_root():
    """API-root metadata for the single API root ``/api1/``."""

    body = {
        "title": "Sheshnaag Intel Fabric",
        "description": (
            "Primary Sheshnaag TAXII API root. Serves one collection per "
            "(tenant × label) pair."
        ),
        "versions": [f"application/taxii+json;version={TAXII_SPEC_VERSION}"],
        "max_content_length": 50 * 1024 * 1024,
    }
    return _taxii_json(body)


@router.get(
    "/api1/collections",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def list_collections(session: Session = Depends(get_sync_session)):
    """List every collection exposed by the API root."""

    items = _list_collections(session)
    body = {"collections": items}
    return _taxii_json(body)


@router.get(
    "/api1/collections/{collection_id}",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def get_collection(
    collection_id: str = Path(...),
    session: Session = Depends(get_sync_session),
):
    """Fetch a single collection's metadata."""

    coll = _find_collection(session, collection_id)
    if coll is None:
        raise HTTPException(status_code=404, detail=f"collection_not_found: {collection_id}")
    return _taxii_json(coll)


@router.get(
    "/api1/collections/{collection_id}/objects",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def list_objects(
    collection_id: str = Path(...),
    range_header: Optional[str] = Header(default=None, alias="Range"),
    limit: Optional[int] = Query(default=None, ge=1, le=500),
    session: Session = Depends(get_sync_session),
):
    """Return a paginated envelope of STIX objects for a collection."""

    tenant, label = _tenant_for_collection(session, collection_id)
    if tenant is None or label is None or label not in _COLLECTION_LABELS:
        raise HTTPException(status_code=404, detail=f"collection_not_found: {collection_id}")

    all_objects = _collect_tenant_objects(session, tenant, label)
    total = len(all_objects)

    start, end_inclusive = _parse_range(range_header)
    if end_inclusive is None:
        if limit is not None:
            end_inclusive = start + limit - 1
        else:
            end_inclusive = total - 1
    end_inclusive = min(end_inclusive, max(total - 1, 0))

    if total == 0:
        window: List[Dict[str, Any]] = []
        status_code = 200
    else:
        if start >= total:
            window = []
            status_code = 200
        else:
            window = all_objects[start : end_inclusive + 1]
            status_code = 206 if (start > 0 or end_inclusive < total - 1) else 200

    envelope = _make_envelope(window, start=start, total=total)
    extra_headers: Dict[str, str] = {}
    if status_code == 206 and window:
        extra_headers["Content-Range"] = (
            f"items {start}-{start + len(window) - 1}/{total}"
        )
    return _taxii_json(envelope, status_code=status_code, extra_headers=extra_headers)


@router.get(
    "/api1/collections/{collection_id}/objects/{object_id}",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def get_object(
    collection_id: str = Path(...),
    object_id: str = Path(...),
    session: Session = Depends(get_sync_session),
):
    """Fetch a single STIX object from a collection."""

    tenant, label = _tenant_for_collection(session, collection_id)
    if tenant is None or label is None:
        raise HTTPException(status_code=404, detail=f"collection_not_found: {collection_id}")

    objects = _collect_tenant_objects(session, tenant, label)
    match = next((o for o in objects if o.get("id") == object_id), None)
    if match is None:
        raise HTTPException(status_code=404, detail=f"object_not_found: {object_id}")
    envelope = {"objects": [match], "more": False}
    return _taxii_json(envelope)


@router.post(
    "/api1/collections/{collection_id}/objects",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def add_objects(
    collection_id: str = Path(...),
    request: Request = None,  # noqa: B008  (FastAPI injects)
    body: Dict[str, Any] = Body(...),
    session: Session = Depends(get_sync_session),
):
    """Ingest a STIX 2.1 Envelope / Bundle into a collection.

    Returns a TAXII Status object. The envelope is validated with
    :meth:`StixExporter.validate_bundle`; malformed inputs produce a
    ``status = "complete", failure_count = N`` result rather than a hard
    400, to match the spec's expectation that Status reports failures
    per-object, not per-request.
    """

    tenant, label = _tenant_for_collection(session, collection_id)
    if tenant is None or label is None:
        raise HTTPException(status_code=404, detail=f"collection_not_found: {collection_id}")

    objects = body.get("objects")
    if not isinstance(objects, list):
        raise HTTPException(status_code=422, detail="envelope must contain 'objects' array")

    # Repack as a bundle so we can hand it to the same validator as the
    # export path. A bundle needs a top-level type + id.
    wrapped_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    exporter = StixExporter(session)
    violations = exporter.validate_bundle(wrapped_bundle)

    successes: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    pending: List[Dict[str, Any]] = []

    store = _INGEST_STORE.setdefault(collection_id, {})
    # Map violations → per-object failure shells. Violation strings start
    # with "objects[N]:" when they are per-object; we key by index.
    bad_indices: Dict[int, List[str]] = {}
    for msg in violations:
        m = re.match(r"^objects\[(\d+)\]", msg)
        if m:
            idx = int(m.group(1))
            bad_indices.setdefault(idx, []).append(msg)

    for idx, obj in enumerate(objects):
        obj_id = obj.get("id") if isinstance(obj, dict) else None
        if not isinstance(obj, dict) or not obj_id:
            failures.append({
                "id": obj_id or f"object--unknown-{idx}",
                "version": _utc_z(),
                "message": "missing id or not an object",
            })
            continue
        if idx in bad_indices:
            failures.append({
                "id": obj_id,
                "version": obj.get("modified") or _utc_z(),
                "message": "; ".join(bad_indices[idx]),
            })
            continue
        store[obj_id] = obj
        successes.append({
            "id": obj_id,
            "version": obj.get("modified") or _utc_z(),
        })

    status_id = f"status--{uuid.uuid4()}"
    report = {
        "id": status_id,
        "status": "complete",
        "request_timestamp": _utc_z(),
        "total_count": len(objects),
        "success_count": len(successes),
        "successes": successes,
        "failure_count": len(failures),
        "failures": failures,
        "pending_count": len(pending),
        "pendings": pending,
    }
    _STATUS_STORE[status_id] = report
    return _taxii_json(report, status_code=202)


@router.get(
    "/api1/collections/{collection_id}/manifest",
    dependencies=[Depends(require_capability("external_disclosure"))],
)
def get_manifest(
    collection_id: str = Path(...),
    range_header: Optional[str] = Header(default=None, alias="Range"),
    session: Session = Depends(get_sync_session),
):
    """Return the per-object manifest for a collection."""

    tenant, label = _tenant_for_collection(session, collection_id)
    if tenant is None or label is None:
        raise HTTPException(status_code=404, detail=f"collection_not_found: {collection_id}")

    all_objects = _collect_tenant_objects(session, tenant, label)
    total = len(all_objects)
    start, end_inclusive = _parse_range(range_header)
    if end_inclusive is None:
        end_inclusive = total - 1
    end_inclusive = min(end_inclusive, max(total - 1, 0))

    window = all_objects[start : end_inclusive + 1] if total else []
    entries = [
        {
            "id": obj.get("id"),
            "date_added": obj.get("created") or _utc_z(),
            "version": obj.get("modified") or obj.get("created") or _utc_z(),
            "media_type": "application/stix+json;version=2.1",
        }
        for obj in window
    ]
    envelope: Dict[str, Any] = {"objects": entries}
    if total:
        envelope["more"] = (start + len(window)) < total
    else:
        envelope["more"] = False
    status_code = 206 if (window and (start > 0 or end_inclusive < total - 1)) else 200
    extra_headers: Dict[str, str] = {}
    if status_code == 206:
        extra_headers["Content-Range"] = (
            f"items {start}-{start + len(window) - 1}/{total}"
        )
    return _taxii_json(envelope, status_code=status_code, extra_headers=extra_headers)


__all__ = ["router", "TAXII_CONTENT_TYPE", "TAXII_SPEC_VERSION"]
