"""Add unique constraint on firewall_rules (agent_id, name, direction)

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-17 00:00:00.000000+00:00

Changes:
  - Remove duplicate firewall_rules rows (keep the most recently updated)
  - Add UNIQUE index on (agent_id, name, direction) to prevent future duplicates
"""

from typing import Sequence, Union

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Step 1: Identify duplicate rule IDs (all except newest per group) ──
    # Build a CTE of IDs to delete
    dup_ids_sql = """
        SELECT id FROM (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY agent_id, name, direction
                       ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
                   ) AS rn
            FROM firewall_rules
        ) ranked
        WHERE rn > 1
    """

    # ── Step 2: Nullify FK references in remediation_actions for duplicates ──
    op.execute(f"""
        UPDATE remediation_actions
        SET rule_id = NULL
        WHERE rule_id IN ({dup_ids_sql})
    """)

    # ── Step 3: Delete revisions for the duplicate rules ──
    op.execute(f"""
        DELETE FROM firewall_rule_revisions
        WHERE rule_id IN ({dup_ids_sql})
    """)

    # ── Step 4: Delete the duplicate firewall_rules rows ──
    op.execute(f"""
        DELETE FROM firewall_rules
        WHERE id IN ({dup_ids_sql})
    """)

    # ── Step 5: Clean up any other orphaned revisions ──
    op.execute("""
        DELETE FROM firewall_rule_revisions
        WHERE rule_id NOT IN (SELECT id FROM firewall_rules)
    """)

    # ── Step 3: Create unique index to prevent future duplicates ──
    op.create_index(
        "uq_firewall_rules_agent_name_direction",
        "firewall_rules",
        ["agent_id", "name", "direction"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_firewall_rules_agent_name_direction", table_name="firewall_rules")
