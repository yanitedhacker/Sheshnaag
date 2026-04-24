"""API route modules."""

from app.api.routes.cve_routes import router as cve_router
from app.api.routes.risk_routes import router as risk_router
from app.api.routes.asset_routes import router as asset_router
from app.api.routes.intel_routes import router as intel_router
from app.api.routes.candidate_routes import router as candidate_router
from app.api.routes.recipe_routes import router as recipe_router
from app.api.routes.run_routes import router as run_router
from app.api.routes.evidence_routes import router as evidence_router
from app.api.routes.artifact_routes import router as artifact_router
from app.api.routes.provenance_routes import router as provenance_router
from app.api.routes.ledger_routes import router as ledger_router
from app.api.routes.disclosure_routes import router as disclosure_router
from app.api.routes.feed_routes import router as feed_router
from app.api.routes.patch_routes import router as patch_router
from app.api.routes.workbench_routes import router as workbench_router
from app.api.routes.graph_routes import router as graph_router
from app.api.routes.simulation_routes import router as simulation_router
from app.api.routes.copilot_routes import router as copilot_router
from app.api.routes.model_routes import router as model_router
from app.api.routes.import_routes import router as import_router
from app.api.routes.governance_routes import router as governance_router
from app.api.routes.auth_routes import router as auth_router
from app.api.routes.tenant_routes import router as tenant_router
from app.api.routes.supply_chain_routes import router as supply_chain_router
from app.api.routes.template_routes import router as template_router
from app.api.routes.review_queue_routes import router as review_queue_router
from app.api.routes.specimen_routes import router as specimen_router
from app.api.routes.specimen_revision_routes import router as specimen_revision_router
from app.api.routes.analysis_case_routes import router as analysis_case_router
from app.api.routes.sandbox_profile_routes import router as sandbox_profile_router
from app.api.routes.finding_routes import router as finding_router
from app.api.routes.indicator_routes import router as indicator_router
from app.api.routes.prevention_routes import router as prevention_router
from app.api.routes.defang_routes import router as defang_router
from app.api.routes.report_routes import router as report_router
from app.api.routes.ai_routes import router as ai_router
from app.api.routes.attack_routes import router as attack_router
from app.api.routes.policy_routes import router as policy_router
from app.api.routes.taxii_routes import router as taxii_router
from app.api.routes.authorization_routes import router as authorization_router
from app.api.routes.capability_routes import router as capability_router
from app.api.routes.live_run_routes import router as live_run_router
from app.api.routes.ops_routes import router as ops_router

__all__ = [
    "cve_router",
    "risk_router",
    "asset_router",
    "intel_router",
    "candidate_router",
    "recipe_router",
    "run_router",
    "evidence_router",
    "artifact_router",
    "provenance_router",
    "ledger_router",
    "disclosure_router",
    "feed_router",
    "patch_router",
    "workbench_router",
    "graph_router",
    "simulation_router",
    "copilot_router",
    "model_router",
    "import_router",
    "governance_router",
    "auth_router",
    "tenant_router",
    "supply_chain_router",
    "template_router",
    "review_queue_router",
    "specimen_router",
    "specimen_revision_router",
    "analysis_case_router",
    "sandbox_profile_router",
    "finding_router",
    "indicator_router",
    "prevention_router",
    "defang_router",
    "report_router",
    "ai_router",
    "attack_router",
    "policy_router",
    "taxii_router",
    "authorization_router",
    "capability_router",
    "live_run_router",
    "ops_router",
]
