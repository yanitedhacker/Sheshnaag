"""V5 W0d — per-tenant JSON-Schema validation for AnalysisCase.custom_fields.

Operators register a JSON Schema document per tenant; subsequent
``custom_fields`` writes are validated against the latest version. No
schema registered for a tenant means "no validation" — the V4 default
behavior is preserved.

The active validator is rebuilt on each call (no caching). For V5 the
schema rarely changes and the cost is negligible; if hot-path latency
becomes a concern, add a per-process cache keyed by
``(tenant_id, schema_version)``.
"""

from __future__ import annotations

from typing import List, Optional

from jsonschema import Draft202012Validator, SchemaError
from sqlalchemy.orm import Session

from app.models.malware_lab import CaseFieldSchema


class CustomFieldsValidationError(ValueError):
    """Raised when ``custom_fields`` violates the active tenant schema.

    The ``errors`` attribute is a list of human-readable error strings,
    one per Draft 2020-12 violation (path + message).
    """

    def __init__(self, errors: List[str]) -> None:
        super().__init__("; ".join(errors) if errors else "validation_failed")
        self.errors = errors


class InvalidSchemaDocumentError(ValueError):
    """Raised when an operator attempts to install a malformed JSON Schema.

    The document itself failed Draft 2020-12 meta-schema validation —
    distinct from runtime field validation against a valid schema.
    """


class CaseFieldSchemaService:
    """Schema CRUD + validation. Per-tenant, per-version."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def install_schema(
        self,
        *,
        tenant_id: int,
        schema: dict,
        actor: str,
    ) -> CaseFieldSchema:
        """Validate the schema document itself, then insert a new version row.

        Auto-increments ``schema_version`` per tenant. Raises
        :class:`InvalidSchemaDocumentError` if the document is not a
        valid Draft 2020-12 schema.
        """

        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as e:
            raise InvalidSchemaDocumentError(str(e)) from e

        latest = self.current_schema(tenant_id)
        next_version = (latest.schema_version + 1) if latest else 1

        row = CaseFieldSchema(
            tenant_id=tenant_id,
            schema_version=next_version,
            schema_doc=schema,
            created_by=actor,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def current_schema(self, tenant_id: int) -> Optional[CaseFieldSchema]:
        """Return the highest-version schema row for the tenant, or None."""
        return (
            self._session.query(CaseFieldSchema)
            .filter_by(tenant_id=tenant_id)
            .order_by(CaseFieldSchema.schema_version.desc())
            .first()
        )

    def validate_custom_fields(
        self, tenant_id: int, fields: dict
    ) -> None:
        """Validate ``fields`` against the tenant's active schema.

        No-op when no schema is registered for the tenant (V4 default).
        Raises :class:`CustomFieldsValidationError` listing every
        violation when the schema rejects the fields.
        """

        active = self.current_schema(tenant_id)
        if active is None:
            return

        validator = Draft202012Validator(active.schema_doc)
        errors: List[str] = []
        for err in sorted(validator.iter_errors(fields), key=lambda e: list(e.path)):
            path = "/".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{path}: {err.message}")

        if errors:
            raise CustomFieldsValidationError(errors)
