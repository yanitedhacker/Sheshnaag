import json
from pathlib import Path
from urllib.error import HTTPError

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.maintainer_routes import router as maintainer_router
from app.core.database import Base, get_sync_session
from app.core.security import TokenData
from app.models import AnalysisCase, MaintainerAssessment, MalwareReport
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.maintainer_assessment_service import MaintainerAssessmentService
from scripts import sheshnaag_maintainer


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


def make_private_tenant(session, slug="oss-maintainer"):
    DemoSeedService(session).seed()
    onboard = AuthService(session).onboard_private_tenant(
        tenant_name="OSS Maintainer",
        tenant_slug=slug,
        admin_email=f"{slug}@example.test",
        admin_password="supersecure123",
        admin_name="OSS Owner",
    )
    tenant = AuthService(session).resolve_private_tenant(token_data=None, tenant_slug=slug)
    return tenant, onboard


def demo_sbom(component_name="edge-gateway"):
    return {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"type": "application", "name": "demo-maintainer-app"}},
        "components": [
            {
                "type": "library",
                "name": component_name,
                "version": "4.2.1",
                "purl": f"pkg:generic/{component_name}@4.2.1",
                "description": "Sanitized test component.",
            }
        ],
    }


def demo_vex():
    return {
        "vulnerabilities": [
            {
                "id": "CVE-2024-10001",
                "status": "affected",
                "analysis": {"state": "affected", "detail": "Maintainer is still triaging."},
                "affects": [{"name": "edge-gateway", "version": "4.2.1"}],
            }
        ]
    }


@pytest.mark.unit
def test_maintainer_assessment_sbom_only_creates_findings():
    session = make_session()
    tenant, _ = make_private_tenant(session)

    result = MaintainerAssessmentService(session).create_assessment(
        tenant,
        repository_url="https://github.com/example/edge-gateway",
        repository_name="edge-gateway",
        sbom=demo_sbom(),
        created_by="OSS Owner",
    )

    assert result["repository"]["name"] == "edge-gateway"
    assert result["summary"]["imports"]["sbom"]["components_processed"] == 1
    assert result["summary"]["matched_findings_count"] >= 1
    assert result["summary"]["top_findings"][0]["cve_id"] == "CVE-2024-10001"


@pytest.mark.unit
def test_maintainer_assessment_with_vex_and_report_export():
    session = make_session()
    tenant, _ = make_private_tenant(session, slug="oss-report")

    result = MaintainerAssessmentService(session).create_assessment(
        tenant,
        repository_url="https://github.com/example/edge-gateway",
        repository_name=None,
        sbom=demo_sbom(),
        vex=demo_vex(),
        created_by="OSS Owner",
        export_report=True,
    )

    assert result["summary"]["imports"]["vex"]["statements_created"] >= 1
    assert result["analysis_case_id"]
    assert result["report_id"]
    assert result["report"]["export_metadata"]["sha256"]
    assert Path(result["report"]["export_metadata"]["path"]).exists()


@pytest.mark.unit
def test_maintainer_assessment_no_matched_advisories_is_safe_empty_result():
    session = make_session()
    tenant, _ = make_private_tenant(session, slug="oss-empty")

    result = MaintainerAssessmentService(session).create_assessment(
        tenant,
        repository_url="https://github.com/example/no-match",
        repository_name="no-match",
        sbom=demo_sbom(component_name="unrelated-library"),
        created_by="OSS Owner",
    )

    assert result["summary"]["matched_findings_count"] == 0
    assert "Keep SBOM generation" in result["summary"]["recommended_next_steps"][0]


@pytest.mark.unit
def test_maintainer_assessment_rejects_invalid_inputs():
    session = make_session()
    tenant, _ = make_private_tenant(session, slug="oss-validation")
    service = MaintainerAssessmentService(session)

    with pytest.raises(ValueError, match="repository_url"):
        service.create_assessment(
            tenant,
            repository_url=" ",
            repository_name=None,
            sbom=demo_sbom(),
            created_by="OSS Owner",
        )

    with pytest.raises(ValueError, match="created_by"):
        service.create_assessment(
            tenant,
            repository_url="https://github.com/example/repo",
            repository_name=None,
            sbom=demo_sbom(),
            created_by=" ",
        )

    with pytest.raises(ValueError, match="components"):
        service.create_assessment(
            tenant,
            repository_url="https://github.com/example/repo",
            repository_name=None,
            sbom={"bomFormat": "CycloneDX", "components": []},
            created_by="OSS Owner",
        )


@pytest.mark.unit
def test_duplicate_maintainer_assessment_is_idempotent():
    session = make_session()
    tenant, _ = make_private_tenant(session, slug="oss-idempotent")
    service = MaintainerAssessmentService(session)

    first = service.create_assessment(
        tenant,
        repository_url="https://github.com/example/edge-gateway",
        repository_name="edge-gateway",
        sbom=demo_sbom(),
        created_by="OSS Owner",
    )
    second = service.create_assessment(
        tenant,
        repository_url="https://github.com/example/edge-gateway",
        repository_name="edge-gateway",
        sbom=demo_sbom(),
        created_by="OSS Owner",
    )

    assert second["id"] == first["id"]
    assert second["idempotent_replay"] is True
    assert session.query(MaintainerAssessment).count() == 1


@pytest.mark.unit
def test_maintainer_export_is_idempotent_and_regenerates_missing_archive_metadata():
    session = make_session()
    tenant, _ = make_private_tenant(session, slug="oss-export-idempotent")
    service = MaintainerAssessmentService(session)
    assessment = service.create_assessment(
        tenant,
        repository_url="https://github.com/example/edge-gateway/",
        repository_name="edge-gateway",
        sbom=demo_sbom(),
        created_by="OSS Owner",
        export_report=True,
        source_refs=[{"url": f"https://example.test/{idx}"} for idx in range(25)],
    )
    first_case_count = session.query(AnalysisCase).count()
    first_report_count = session.query(MalwareReport).count()
    report_id = assessment["report_id"]

    again = service.export_assessment(tenant, assessment_id=assessment["id"])

    assert again["report_id"] == report_id
    assert session.query(AnalysisCase).count() == first_case_count
    assert session.query(MalwareReport).count() == first_report_count
    assert len(again["source_refs"]) == MaintainerAssessmentService.MAX_SOURCE_REFS

    report = session.query(MalwareReport).filter(MalwareReport.id == report_id).one()
    report.export_metadata = {}
    session.flush()
    regenerated = service.export_assessment(tenant, assessment_id=assessment["id"])

    assert regenerated["report_id"] == report_id
    assert regenerated["report"]["export_metadata"]["sha256"]
    assert Path(regenerated["report"]["export_metadata"]["path"]).exists()
    assert session.query(AnalysisCase).count() == first_case_count
    assert session.query(MalwareReport).count() == first_report_count


@pytest.mark.unit
def test_maintainer_api_create_get_export_with_auth_override():
    session = make_session()
    tenant, onboard = make_private_tenant(session, slug="oss-api")
    user_id = onboard["user"]["id"]
    token_data = TokenData(
        username=onboard["user"]["email"],
        user_id=user_id,
        scopes=["tenant:read", "tenant:write"],
        memberships=onboard["memberships"],
    )

    app = FastAPI()
    app.include_router(maintainer_router)

    def override_session():
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_sync_session] = override_session

    from app.api.routes import maintainer_routes

    app.dependency_overrides[maintainer_routes.verify_token_optional] = lambda: token_data

    client = TestClient(app)
    created = client.post(
        "/api/maintainer/assessments",
        json={
            "tenant_slug": tenant.slug,
            "repository_url": "https://github.com/example/edge-gateway",
            "sbom": demo_sbom(),
            "created_by": "OSS Owner",
        },
    )
    assert created.status_code == 200
    assessment_id = created.json()["id"]

    fetched = client.get(f"/api/maintainer/assessments/{assessment_id}", params={"tenant_slug": tenant.slug})
    assert fetched.status_code == 200
    assert fetched.json()["id"] == assessment_id

    exported = client.post(f"/api/maintainer/assessments/{assessment_id}/export", params={"tenant_slug": tenant.slug})
    assert exported.status_code == 200
    assert exported.json()["report_id"]


@pytest.mark.unit
def test_maintainer_api_invalid_tenant_returns_400():
    session = make_session()
    make_private_tenant(session, slug="oss-invalid")
    app = FastAPI()
    app.include_router(maintainer_router)

    def override_session():
        yield session

    app.dependency_overrides[get_sync_session] = override_session
    client = TestClient(app)
    response = client.post(
        "/api/maintainer/assessments",
        json={
            "tenant_slug": "missing-tenant",
            "repository_url": "https://github.com/example/missing",
            "sbom": demo_sbom(),
            "created_by": "OSS Owner",
        },
    )
    assert response.status_code == 400


@pytest.mark.unit
def test_maintainer_api_validation_returns_400():
    session = make_session()
    tenant, onboard = make_private_tenant(session, slug="oss-api-validation")
    token_data = TokenData(
        username=onboard["user"]["email"],
        user_id=onboard["user"]["id"],
        scopes=["tenant:read", "tenant:write"],
        memberships=onboard["memberships"],
    )
    app = FastAPI()
    app.include_router(maintainer_router)

    def override_session():
        yield session

    app.dependency_overrides[get_sync_session] = override_session
    from app.api.routes import maintainer_routes

    app.dependency_overrides[maintainer_routes.verify_token_optional] = lambda: token_data
    client = TestClient(app)
    response = client.post(
        "/api/maintainer/assessments",
        json={
            "tenant_slug": tenant.slug,
            "repository_url": " ",
            "sbom": {"components": []},
            "created_by": " ",
        },
    )

    assert response.status_code == 400


@pytest.mark.unit
def test_maintainer_cli_assess_json_and_auth_header(monkeypatch, tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps(demo_sbom()), encoding="utf-8")
    calls = {}

    def fake_request(method, url, *, token=None, payload=None, output=None):
        calls["method"] = method
        calls["url"] = url
        calls["token"] = token
        calls["payload"] = payload
        return {"id": 7, "summary": {"matched_findings_count": 0, "top_findings": []}}

    monkeypatch.setattr(sheshnaag_maintainer, "_request_json", fake_request)
    rc = sheshnaag_maintainer.main(
        [
            "assess",
            "--base-url",
            "http://127.0.0.1:8000",
            "--tenant-slug",
            "oss",
            "--repo-url",
            "https://github.com/example/repo",
            "--sbom",
            str(sbom_path),
            "--token",
            "test-token",
            "--json",
        ]
    )

    assert rc == 0
    assert calls["method"] == "POST"
    assert calls["token"] == "test-token"
    assert calls["payload"]["sbom"]["components"][0]["name"] == "edge-gateway"


@pytest.mark.unit
def test_maintainer_cli_auth_failure_message(monkeypatch, capsys):
    def fake_request(*args, **kwargs):
        raise HTTPError(url="http://api", code=401, msg="Unauthorized", hdrs=None, fp=None)

    monkeypatch.setattr(sheshnaag_maintainer, "_request_json", fake_request)
    rc = sheshnaag_maintainer.main(["show", "--base-url", "http://127.0.0.1:8000", "--assessment-id", "1"])

    assert rc == 2
    assert "Authentication required" in capsys.readouterr().err


@pytest.mark.unit
def test_maintainer_cli_export_output_download(monkeypatch, tmp_path):
    output_path = tmp_path / "assessment.zip"
    calls = []

    def fake_request(method, url, *, token=None, payload=None, output=None):
        calls.append({"method": method, "url": url, "token": token, "output": output})
        if output:
            Path(output).write_bytes(b"zip-bytes")
            return {"output": output, "bytes": 9}
        return {
            "id": 3,
            "report": {
                "id": 11,
                "status": "approved",
                "download_url": "/api/reports/11/download?tenant_slug=oss",
            },
            "summary": {"matched_findings_count": 1, "top_findings": []},
        }

    monkeypatch.setattr(sheshnaag_maintainer, "_request_json", fake_request)
    rc = sheshnaag_maintainer.main(
        [
            "export",
            "--base-url",
            "http://127.0.0.1:8000",
            "--tenant-slug",
            "oss",
            "--assessment-id",
            "3",
            "--output",
            str(output_path),
            "--token",
            "test-token",
        ]
    )

    assert rc == 0
    assert output_path.read_bytes() == b"zip-bytes"
    assert calls[0]["method"] == "POST"
    assert calls[1]["method"] == "GET"
    assert calls[1]["output"] == str(output_path)
