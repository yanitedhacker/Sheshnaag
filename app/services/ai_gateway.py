"""Grounded explanation gateway.

This layer deliberately keeps ranking and scheduling deterministic. It only
turns already-retrieved evidence into operator-friendly explanations.
"""

from __future__ import annotations

from typing import Dict, List


class AIGatewayService:
    """Synthesize markdown strictly from supplied evidence."""

    def synthesize(
        self,
        *,
        intent: str,
        query: str,
        structured_context: dict,
        retrieved_chunks: List[dict],
    ) -> dict:
        """Return answer markdown and citations without inventing unsupported facts."""
        if intent == "why_top_action":
            return self._why_top_action(structured_context, retrieved_chunks)
        if intent == "attack_paths":
            return self._attack_paths(structured_context, retrieved_chunks)
        if intent == "cab_memo":
            return self._cab_memo(structured_context, retrieved_chunks)
        if intent == "weekly_summary":
            return self._weekly_summary(structured_context, retrieved_chunks)
        return {
            "answer_markdown": "",
            "confidence": 0.0,
            "cannot_answer_reason": "I could not ground that request with supported evidence.",
        }

    def _why_top_action(self, context: dict, chunks: List[dict]) -> dict:
        action = context["action"]
        evidence_lines = "\n".join(
            f"- {item['title']}: {item['summary']}" for item in action.get("evidence", [])[:4]
        )
        source_lines = "\n".join(
            f"- {chunk['title']}: {chunk['content'][:180].strip()}" for chunk in chunks[:3]
        )
        return {
            "answer_markdown": (
                f"## Why `{action['title']}` is ranked first\n\n"
                f"- Recommended action: `{action['recommended_action']}`\n"
                f"- Actionable risk score: `{action['actionable_risk_score']}`\n"
                f"- Confidence: `{action['confidence']}`\n"
                f"- Approval state: `{action.get('approval_state', 'pending_review')}`\n\n"
                f"### Evidence\n{evidence_lines or '- No structured evidence available.'}\n\n"
                f"### Retrieved Context\n{source_lines or '- No additional documents matched the query.'}"
            ),
            "confidence": min(0.96, action["confidence"] + (0.02 * min(3, len(chunks)))),
            "cannot_answer_reason": None,
        }

    def _attack_paths(self, context: dict, chunks: List[dict]) -> dict:
        asset_name = context["asset_name"]
        paths = context["paths"]
        path_lines = "\n".join(f"- `{path['summary']}` (score `{path['score']}`)" for path in paths[:5])
        source_lines = "\n".join(f"- {chunk['title']}: {chunk['content'][:160].strip()}" for chunk in chunks[:3])
        return {
            "answer_markdown": (
                f"## Attack Paths for `{asset_name}`\n\n"
                f"{path_lines or '- No persisted paths were found.'}\n\n"
                f"### Supporting Context\n{source_lines or '- No additional documents matched the asset context.'}"
            ),
            "confidence": 0.82 if paths else 0.0,
            "cannot_answer_reason": None if paths else "No attack path evidence was found for that asset.",
        }

    def _cab_memo(self, context: dict, chunks: List[dict]) -> dict:
        actions = context["actions"]
        lines = "\n".join(
            f"- `{action['title']}` -> `{action['recommended_action']}` "
            f"(risk `{action['actionable_risk_score']}`, approval `{action.get('approval_state', 'pending_review')}`)"
            for action in actions[:4]
        )
        source_lines = "\n".join(f"- {chunk['title']}: {chunk['content'][:150].strip()}" for chunk in chunks[:4])
        return {
            "answer_markdown": (
                "## CAB-Ready Patch Memo\n\n"
                "### Highest-Priority Actions\n"
                f"{lines or '- No actions available.'}\n\n"
                "### Evidence Sources\n"
                f"{source_lines or '- No supporting documents were retrieved.'}"
            ),
            "confidence": 0.78 if actions else 0.0,
            "cannot_answer_reason": None if actions else "There are no actions available to summarize.",
        }

    def _weekly_summary(self, context: dict, chunks: List[dict]) -> dict:
        actions = context["actions"]
        stats = context.get("stats", {})
        source_lines = "\n".join(f"- {chunk['title']}: {chunk['content'][:150].strip()}" for chunk in chunks[:4])
        lines = "\n".join(
            f"- `{action['title']}`: score `{action['actionable_risk_score']}`, paths `{action['attack_path_count']}`"
            for action in actions[:5]
        )
        return {
            "answer_markdown": (
                "## Weekly Risk Summary\n\n"
                f"- Exposed assets: `{stats.get('exposed_assets', 0)}`\n"
                f"- Crown-jewel assets: `{stats.get('crown_jewel_assets', 0)}`\n"
                f"- Top actionable risk: `{stats.get('top_actionable_risk_score', 0)}`\n\n"
                "### Top Items\n"
                f"{lines or '- No ranked actions.'}\n\n"
                "### Supporting Evidence\n"
                f"{source_lines or '- No retrieved documents.'}"
            ),
            "confidence": 0.76 if actions else 0.0,
            "cannot_answer_reason": None if actions else "There is not enough ranked data to summarize this week.",
        }
