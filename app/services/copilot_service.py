"""Grounded copilot responses backed by structured data and citations."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.v2 import Tenant
from app.services.ai_gateway import AIGatewayService
from app.services.graph_service import ExposureGraphService
from app.services.knowledge_service import KnowledgeRetrievalService
from app.services.workbench_service import WorkbenchService


class CopilotService:
    """Provide safe, grounded responses without inventing entities."""

    def __init__(self, session: Session):
        self.session = session
        self.workbench = WorkbenchService(session)
        self.graph = ExposureGraphService(session)
        self.knowledge = KnowledgeRetrievalService(session)
        self.ai_gateway = AIGatewayService()

    def answer(self, tenant: Tenant, query: str) -> Dict[str, object]:
        """Return a grounded answer using structured retrieval and source-backed evidence."""
        normalized = query.lower().strip()
        workbench = self.workbench.get_summary(tenant, limit=10)

        if not workbench["actions"]:
            return self._cannot_answer("There are no ranked actions for this tenant yet.")

        intent = self._classify_intent(normalized)
        if intent == "why_top_action":
            top = workbench["actions"][0]
            cve_refs = [entity["id"] for entity in top["entity_refs"] if entity["type"] == "cve"]
            cve_db_ids = [cve.id for cve in self._cve_records_for_ids(cve_refs)]
            chunks = self.knowledge.retrieve(query=query, tenant=tenant, cve_db_ids=cve_db_ids, limit=5)
            synthesis = self.ai_gateway.synthesize(
                intent=intent,
                query=query,
                structured_context={"action": top},
                retrieved_chunks=chunks,
            )
            return self._response_from_context(
                synthesis=synthesis,
                citations=self._merge_citations(top["citations"], chunks),
                supporting_entities=top["entity_refs"],
            )

        if intent == "attack_paths":
            asset = self._match_asset(tenant, normalized)
            if asset is None:
                return self._cannot_answer("I could not match an asset name from the question.")
            graph = self.graph.get_attack_paths(tenant, asset_id=asset.id, limit=5)
            chunks = self.knowledge.retrieve(query=query, tenant=tenant, limit=4)
            synthesis = self.ai_gateway.synthesize(
                intent=intent,
                query=query,
                structured_context={"asset_name": asset.name, "paths": graph["paths"]},
                retrieved_chunks=chunks,
            )
            return self._response_from_context(
                synthesis=synthesis,
                citations=self._merge_citations([], chunks),
                supporting_entities=[{"type": "asset", "id": str(asset.id), "label": asset.name}],
            )

        if intent in {"cab_memo", "weekly_summary"}:
            actions = workbench["actions"][:3]
            cve_refs = [entity["id"] for action in actions for entity in action["entity_refs"] if entity["type"] == "cve"]
            cve_db_ids = [cve.id for cve in self._cve_records_for_ids(cve_refs)]
            chunks = self.knowledge.retrieve(query=query, tenant=tenant, cve_db_ids=cve_db_ids, limit=6)
            citations = [citation for action in actions for citation in action["citations"]]
            synthesis = self.ai_gateway.synthesize(
                intent=intent,
                query=query,
                structured_context={"actions": actions, "stats": workbench["summary"]},
                retrieved_chunks=chunks,
            )
            return self._response_from_context(
                synthesis=synthesis,
                citations=self._merge_citations(citations, chunks),
                supporting_entities=[entity for action in actions for entity in action["entity_refs"][:2]],
            )

        return self._cannot_answer("Supported prompts include ranking explanations, attack path summaries, and CAB-style weekly memos.")

    def _match_asset(self, tenant: Tenant, query: str) -> Optional[Asset]:
        assets = self.session.query(Asset).filter(Asset.tenant_id == tenant.id).all()
        for asset in assets:
            if asset.name.lower() in query:
                return asset
        return None

    @staticmethod
    def _classify_intent(normalized_query: str) -> str:
        if "attack path" in normalized_query or "attack paths" in normalized_query:
            return "attack_paths"
        if "cab" in normalized_query or "memo" in normalized_query:
            return "cab_memo"
        if "this week" in normalized_query or "week's top risks" in normalized_query or "top risks" in normalized_query:
            return "weekly_summary"
        if "ranked first" in normalized_query or normalized_query.startswith("why"):
            return "why_top_action"
        return "unknown"

    def _cve_records_for_ids(self, cve_ids: Sequence[str]):
        from app.models.cve import CVE

        wanted = [cve_id.upper() for cve_id in cve_ids if cve_id]
        if not wanted:
            return []
        return self.session.query(CVE).filter(CVE.cve_id.in_(wanted)).all()

    @staticmethod
    def _merge_citations(existing: List[dict], chunks: List[dict]) -> List[dict]:
        merged: Dict[str, dict] = {}
        for citation in existing:
            if citation.get("url"):
                merged[citation["url"]] = citation
        for chunk in chunks:
            if chunk.get("source_url"):
                merged[chunk["source_url"]] = {"label": chunk.get("source_label") or chunk["document_type"], "url": chunk["source_url"]}
        return list(merged.values())

    @staticmethod
    def _response_from_context(*, synthesis: dict, citations: List[dict], supporting_entities: List[dict]) -> Dict[str, object]:
        return {
            "answer_markdown": synthesis.get("answer_markdown", ""),
            "citations": citations,
            "supporting_entities": supporting_entities,
            "confidence": round(float(synthesis.get("confidence", 0.0)), 2),
            "cannot_answer_reason": synthesis.get("cannot_answer_reason"),
        }

    @staticmethod
    def _cannot_answer(reason: str) -> Dict[str, object]:
        return {
            "answer_markdown": "",
            "citations": [],
            "supporting_entities": [],
            "confidence": 0.0,
            "cannot_answer_reason": reason,
        }
