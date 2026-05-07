"""V5 W2b integration models — chat <-> case links."""

from __future__ import annotations

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class CaseIntegrationLink(Base):
    """Maps a Sheshnaag analysis_case to a chat-platform-side artifact.

    Used by inbound webhook handlers to look up the case for a given
    Slack message / Linear issue / JIRA issue.
    """

    __tablename__ = "case_integration_links"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "external_id",
            name="uq_case_integration_provider_external",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(
        Integer,
        ForeignKey("analysis_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider = Column(String(20), nullable=False, index=True)
    external_id = Column(String(255), nullable=False)
    metadata_json = Column("metadata", JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    created_by = Column(String(200), nullable=True)
