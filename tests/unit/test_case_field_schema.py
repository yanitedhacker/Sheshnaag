"""Unit tests for V5 W0d CaseFieldSchemaService."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers tables
from app.core.database import Base
from app.models.malware_lab import CaseFieldSchema
from app.models.v2 import Tenant
from app.services.case_field_schema import (
    CaseFieldSchemaService,
    CustomFieldsValidationError,
    InvalidSchemaDocumentError,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    sess.add(Tenant(id=1, slug="t1", name="T1"))
    sess.add(Tenant(id=2, slug="t2", name="T2"))
    sess.commit()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


SAMPLE_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "incident_id": {"type": "string", "minLength": 1},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["incident_id", "severity"],
    "additionalProperties": False,
}


def test_install_schema_first_version_is_one(session):
    svc = CaseFieldSchemaService(session)
    row = svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="lead@x")
    assert row.schema_version == 1
    assert row.tenant_id == 1
    assert row.created_by == "lead@x"


def test_install_schema_increments_per_tenant(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    svc.install_schema(tenant_id=2, schema=SAMPLE_SCHEMA, actor="x")

    t1_rows = (
        session.query(CaseFieldSchema)
        .filter_by(tenant_id=1)
        .order_by(CaseFieldSchema.schema_version)
        .all()
    )
    t2_rows = (
        session.query(CaseFieldSchema)
        .filter_by(tenant_id=2)
        .order_by(CaseFieldSchema.schema_version)
        .all()
    )
    assert [r.schema_version for r in t1_rows] == [1, 2]
    assert [r.schema_version for r in t2_rows] == [1]


def test_install_schema_rejects_invalid_document(session):
    svc = CaseFieldSchemaService(session)
    bad = {"type": "not_a_real_type"}
    with pytest.raises(InvalidSchemaDocumentError):
        svc.install_schema(tenant_id=1, schema=bad, actor="x")


def test_current_schema_returns_latest(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    second = svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")

    current = svc.current_schema(tenant_id=1)
    assert current is not None
    assert current.id == second.id
    assert current.schema_version == 2


def test_current_schema_returns_none_when_unset(session):
    svc = CaseFieldSchemaService(session)
    assert svc.current_schema(tenant_id=1) is None


def test_validate_custom_fields_no_op_without_schema(session):
    svc = CaseFieldSchemaService(session)
    # No schema installed for tenant 1 — anything passes.
    svc.validate_custom_fields(tenant_id=1, fields={"anything": "goes"})


def test_validate_custom_fields_passes_valid(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    svc.validate_custom_fields(
        tenant_id=1,
        fields={"incident_id": "INC-42", "severity": "high"},
    )


def test_validate_custom_fields_rejects_missing_required(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    with pytest.raises(CustomFieldsValidationError) as exc:
        svc.validate_custom_fields(tenant_id=1, fields={"incident_id": "INC-42"})
    assert any("severity" in e for e in exc.value.errors)


def test_validate_custom_fields_rejects_wrong_enum(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    with pytest.raises(CustomFieldsValidationError) as exc:
        svc.validate_custom_fields(
            tenant_id=1,
            fields={"incident_id": "INC-42", "severity": "blue"},
        )
    assert any("severity" in e for e in exc.value.errors)


def test_validate_custom_fields_rejects_additional_properties(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    with pytest.raises(CustomFieldsValidationError):
        svc.validate_custom_fields(
            tenant_id=1,
            fields={
                "incident_id": "INC-42",
                "severity": "high",
                "rogue_field": "nope",
            },
        )


def test_validate_collects_multiple_errors(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    with pytest.raises(CustomFieldsValidationError) as exc:
        # Missing required, wrong type for tags, wrong severity enum.
        svc.validate_custom_fields(
            tenant_id=1,
            fields={"severity": "off-the-charts", "tags": "should-be-list"},
        )
    # We expect at least 3 errors collected.
    assert len(exc.value.errors) >= 3


def test_validate_isolates_per_tenant(session):
    svc = CaseFieldSchemaService(session)
    svc.install_schema(tenant_id=1, schema=SAMPLE_SCHEMA, actor="x")
    # Tenant 2 has no schema — anything should pass.
    svc.validate_custom_fields(tenant_id=2, fields={"foo": "bar"})
