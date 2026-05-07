# V5 Wave 0 — W0d (Custom case fields) Plan

**Goal:** Per-tenant JSON-Schema-validated custom fields on `AnalysisCase`, without building a schema-builder UI.

**Architecture:** `analysis_cases.custom_fields` is a JSON column. Each tenant has zero or more rows in `case_field_schema` (versioned); the *latest* row per tenant is the active schema. On case write, the application calls `CaseFieldSchemaService.validate_custom_fields(tenant_id, fields)` which delegates to `jsonschema.Draft202012Validator`. No schema = anything goes (V4 default behavior preserved).

**Tech Stack:** SQLAlchemy + Alembic + `jsonschema` 4.x (Draft 2020-12). `jsonschema` is currently a transitive dep — V5 promotes it to an explicit one in `requirements.txt`.

## Deviation from orchestration plan

The original plan put validation in `app/services/case_workflow.py`. W0d puts it in a dedicated `app/services/case_field_schema.py` instead — cleaner single-responsibility (workflow = state machine; schema = field validation), and the two have independent change cadences. `case_workflow.py` does not need to import `jsonschema`.

## File structure

| Action | File | Responsibility |
|---|---|---|
| Modify | `app/models/malware_lab.py` | Add `custom_fields` JSON column to `AnalysisCase`. New `CaseFieldSchema` model. |
| Modify | `app/models/__init__.py` | Export `CaseFieldSchema`. |
| Create | `app/migrations/versions/v5a03_custom_case_fields.py` | Add `custom_fields` JSON column to `analysis_cases`; create `case_field_schema` table; up + down. |
| Create | `app/services/case_field_schema.py` | `CaseFieldSchemaService` with `install_schema`, `current_schema`, `validate_custom_fields`. `CustomFieldsValidationError`. |
| Modify | `requirements.txt` | Promote `jsonschema>=4` from transitive to explicit. |
| Create | `tests/unit/test_case_field_schema.py` | Service unit tests. |

## `CaseFieldSchema` shape

```python
class CaseFieldSchema(Base):
    __tablename__ = "case_field_schemas"
    __table_args__ = (
        UniqueConstraint("tenant_id", "schema_version", name="uq_case_field_schema_version"),
    )

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    schema_version = Column(Integer, nullable=False)
    schema = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    created_by = Column(String(200), nullable=False)
```

- `(tenant_id, schema_version)` is unique. Service auto-increments `schema_version` per tenant.
- The `schema` column holds a full JSON Schema (Draft 2020-12) document. Operators register a schema via API; we don't ship a schema-builder UI.

## Service shape

```python
class CustomFieldsValidationError(ValueError):
    """Raised when custom_fields fails validation against the active schema."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class CaseFieldSchemaService:
    def __init__(self, session: Session) -> None: ...

    def install_schema(self, *, tenant_id: int, schema: dict, actor: str) -> CaseFieldSchema:
        """Validate the schema document itself, then insert a new version row."""

    def current_schema(self, tenant_id: int) -> Optional[CaseFieldSchema]:
        """Return the highest-version schema row for the tenant, or None."""

    def validate_custom_fields(self, tenant_id: int, fields: dict) -> None:
        """Validate fields against the tenant's active schema. No-op if no schema.

        Raises CustomFieldsValidationError listing every Draft 2020-12 error path.
        """
```

## Out of scope for W0d

- Per-field permissions (which roles may write which fields). Add when V6 needs it.
- Schema migration tooling (e.g., a "migrate cases when the schema changes" job). Future work.
- A schema-builder UI in the operator console. PRD explicitly defers.

## Acceptance

- Migration up + down clean on sqlite.
- `CaseFieldSchemaService.validate_custom_fields` rejects invalid `custom_fields` with one `CustomFieldsValidationError` listing all Draft 2020-12 violations.
- Calling validate when no schema exists for a tenant is a no-op (V4 behavior preserved).
- Installing an *invalid JSON Schema document itself* raises (uses `Draft202012Validator.check_schema`).
- `jsonschema` is in `requirements.txt`.
