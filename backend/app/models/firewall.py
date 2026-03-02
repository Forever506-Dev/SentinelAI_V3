"""
Firewall Models

Tracks firewall rules synced from agents, rule revisions for versioning,
and firewall policies for centralized management.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Index, String, Boolean, DateTime, Integer, Text, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class FirewallRule(Base):
    """A firewall rule tracked in the database (synced from agent)."""

    __tablename__ = "firewall_rules"
    __table_args__ = (
        Index("ix_firewall_rules_agent_direction_action", "agent_id", "direction", "action"),
        Index("ix_firewall_rules_agent_enabled", "agent_id", "enabled"),
        UniqueConstraint("agent_id", "name", "direction", name="uq_firewall_rules_agent_name_direction"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Target Agent ---
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True
    )

    # --- Rule Specification ---
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    direction: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # inbound | outbound
    action: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # allow | block
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, default="any"
    )  # tcp | udp | any | icmp
    local_port: Mapped[str] = mapped_column(String(100), nullable=True, default="any")
    remote_port: Mapped[str] = mapped_column(String(100), nullable=True, default="any")
    local_address: Mapped[str] = mapped_column(String(255), nullable=True, default="any")
    remote_address: Mapped[str] = mapped_column(String(255), nullable=True, default="any")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    profile: Mapped[str] = mapped_column(String(50), nullable=True, default="any")
    profiles: Mapped[list[str]] = mapped_column(
        ARRAY(String(20)), nullable=False, server_default="{}", default=list
    )

    # --- Policy Link ---
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("firewall_policies.id"), nullable=True
    )

    # --- Sync Status ---
    synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    drift_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    current_version: Mapped[int] = mapped_column(Integer, default=1)

    # --- Audit ---
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<FirewallRule(id={self.id}, agent_id={self.agent_id}, "
            f"name={self.name}, action={self.action})>"
        )


class FirewallRuleRevision(Base):
    """Version history for a firewall rule change."""

    __tablename__ = "firewall_rule_revisions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("firewall_rules.id"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- What changed ---
    diff: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # --- Who changed it ---
    changed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    change_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<FirewallRuleRevision(rule_id={self.rule_id}, version={self.version})>"


class FirewallPolicy(Base):
    """A named set of firewall rules that can be assigned to agents."""

    __tablename__ = "firewall_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Policy Content ---
    rules: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    default_inbound_action: Mapped[str] = mapped_column(
        String(20), nullable=False, default="block"
    )
    default_outbound_action: Mapped[str] = mapped_column(
        String(20), nullable=False, default="allow"
    )

    # --- Assignment tracking ---
    assigned_agent_count: Mapped[int] = mapped_column(Integer, default=0)

    # --- Audit ---
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    # --- Timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<FirewallPolicy(id={self.id}, name={self.name})>"
