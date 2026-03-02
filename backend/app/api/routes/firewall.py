"""
Firewall Routes (Phase 2)

Full CRUD for firewall rules with RBAC, HMAC-signed commands,
approval workflow for destructive actions, drift detection, policies,
and advanced filtering/search.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc, or_, cast, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import get_db
from app.core.security import require_role, sign_command
from app.core.config import settings
from app.models.agent import Agent
from app.models.firewall import FirewallRule, FirewallRuleRevision, FirewallPolicy
from app.models.remediation import RemediationAction
from app.schemas.firewall import (
    FirewallRuleCreate,
    FirewallRuleUpdate,
    FirewallRuleResponse,
    FirewallRuleListResponse,
    FirewallRuleToggleRequest,
    FirewallPolicyCreate,
    FirewallPolicyResponse,
    FirewallPolicyListResponse,
    LiveFirewallRulesResponse,
    FirewallSnapshotResponse,
)
from app.services.firewall_service import (
    relay_signed_command,
    record_remediation,
    create_approval_request,
    track_rule,
    create_revision,
    check_self_block,
)

logger = structlog.get_logger()
router = APIRouter()


# ═══════════════════════════════════════════════════════════════════
# Live Rules (relayed from agent)
# ═══════════════════════════════════════════════════════════════════


@router.get("/{agent_id}/live-rules")
async def get_live_firewall_rules(
    agent_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fetch live firewall rules from the agent in real time."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    cmd_result = await relay_signed_command(agent_id, "firewall_list", {}, timeout_secs=60)

    return {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "os_type": agent.os_type,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
        "rules": cmd_result.get("data", {}).get("rules", []) if cmd_result.get("data") else [],
        "total": cmd_result.get("data", {}).get("total", 0) if cmd_result.get("data") else 0,
    }


# ═══════════════════════════════════════════════════════════════════
# Tracked Rules CRUD
# ═══════════════════════════════════════════════════════════════════


@router.get("/{agent_id}/rules", response_model=FirewallRuleListResponse)
async def list_tracked_rules(
    agent_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str = Query("", description="Partial name match (case-insensitive)"),
    direction: str = Query("", description="Filter: inbound | outbound"),
    action: str = Query("", description="Filter: allow | block"),
    enabled: str = Query("", description="Filter: true | false"),
    profile: str = Query("", description="Filter: domain | private | public"),
    sort_by: str = Query("created_at", description="Sort field: name | direction | action | created_at | updated_at"),
    sort_dir: str = Query("desc", description="Sort direction: asc | desc"),
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List tracked firewall rules for an agent with advanced filtering.

    Supports:
      - **search**: partial name match via trigram index (ILIKE)
      - **direction**: exact match on inbound/outbound
      - **action**: exact match on allow/block
      - **enabled**: filter by enabled state
      - **profile**: filter rules containing a specific profile in the profiles array
      - **sort_by** + **sort_dir**: flexible sorting
      - **pagination**: page + page_size
    """
    query = select(FirewallRule).where(FirewallRule.agent_id == agent_id)
    filters_applied: dict[str, str] = {}

    # ── Search (ILIKE for partial name match) ──
    if search.strip():
        query = query.where(FirewallRule.name.ilike(f"%{search.strip()}%"))
        filters_applied["search"] = search.strip()

    # ── Direction filter ──
    if direction and direction.lower() in ("inbound", "outbound"):
        query = query.where(FirewallRule.direction == direction.lower())
        filters_applied["direction"] = direction.lower()

    # ── Action filter ──
    if action and action.lower() in ("allow", "block"):
        query = query.where(FirewallRule.action == action.lower())
        filters_applied["action"] = action.lower()

    # ── Enabled filter ──
    if enabled.lower() in ("true", "false"):
        val = enabled.lower() == "true"
        query = query.where(FirewallRule.enabled == val)
        filters_applied["enabled"] = str(val).lower()

    # ── Profile filter (uses @> "contains" operator on the profiles ARRAY) ──
    if profile and profile.lower() in ("domain", "private", "public"):
        query = query.where(
            FirewallRule.profiles.any(profile.lower())
        )
        filters_applied["profile"] = profile.lower()

    # ── Sorting ──
    allowed_sorts = {"name", "direction", "action", "created_at", "updated_at", "enabled", "protocol"}
    sort_field = sort_by if sort_by in allowed_sorts else "created_at"
    sort_col = getattr(FirewallRule, sort_field)
    if sort_dir.lower() == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    # ── Count total (before pagination) ──
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # ── Pagination ──
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    rules = result.scalars().all()

    return {
        "rules": rules,
        "total": total,
        "page": page,
        "page_size": page_size,
        "filters_applied": filters_applied,
    }


@router.post("/{agent_id}/rules")
async def add_firewall_rule(
    agent_id: str,
    req: FirewallRuleCreate,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add a firewall rule on the agent (analysts+). Signed with HMAC."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Self-block prevention
    if req.action == "block" and check_self_block(req.remote_address):
        raise HTTPException(
            status_code=400,
            detail="Cannot block the backend/panel IP address (self-block prevention)",
        )

    params = {
        "name": req.name,
        "direction": req.direction,
        "action": req.action,
        "protocol": req.protocol,
        "port": req.local_port,
        "remote_address": req.remote_address,
        "profiles": req.profiles or [],
    }

    cmd_result = await relay_signed_command(agent_id, "firewall_add", params)
    signature = sign_command(params)

    action = await record_remediation(
        db, agent_id, "firewall_add", current_user.get("sub"),
        params, cmd_result, req.reason, signature=signature,
    )

    # Track in DB if successful
    if cmd_result.get("status") == "completed":
        await track_rule(db, agent_id, req.model_dump(), current_user.get("sub"))

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.put("/{agent_id}/rules/{rule_id}")
async def edit_firewall_rule(
    agent_id: str,
    rule_id: str,
    req: FirewallRuleUpdate,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Edit an existing tracked firewall rule. Requires approval for analysts."""
    result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.id == rule_id)
        .where(FirewallRule.agent_id == agent_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Tracked rule not found")

    # Self-block check
    new_remote = req.remote_address or rule.remote_address
    new_action = req.action or rule.action
    if new_action == "block" and check_self_block(new_remote):
        raise HTTPException(
            status_code=400,
            detail="Cannot block the backend/panel IP address (self-block prevention)",
        )

    # Build diff
    diff = {}
    updates = req.model_dump(exclude_unset=True, exclude={"reason"})
    for field, new_val in updates.items():
        old_val = getattr(rule, field, None)
        if old_val != new_val:
            diff[field] = {"old": old_val, "new": new_val}
            setattr(rule, field, new_val)

    if not diff:
        return {"status": "no_changes", "output": "No fields changed"}

    # Ensure SQLAlchemy detects mutable field changes (ARRAY columns)
    if "profiles" in diff:
        flag_modified(rule, "profiles")
    await db.flush()

    user_role = current_user.get("role", "analyst")

    # Analysts need approval for edits; admins+ auto-approve
    if _role_level(user_role) < _role_level("admin"):
        # Create pending remediation + approval
        pending_action = await record_remediation(
            db, agent_id, "firewall_edit", current_user.get("sub"),
            {"rule_id": str(rule_id), **updates}, {"status": "pending_approval"},
            req.reason,
        )
        pending_action.status = "pending_approval"
        approval = await create_approval_request(
            db, str(pending_action.id), current_user.get("sub"), req.reason,
        )
        return {
            "status": "pending_approval",
            "approval_id": str(approval.id),
            "remediation_id": str(pending_action.id),
            "output": "Edit requires admin approval",
        }

    # Admin/superadmin: apply immediately
    params = {"name": rule.name, "direction": rule.direction, "action": rule.action,
              "protocol": rule.protocol, "port": rule.local_port, "remote_address": rule.remote_address,
              "profiles": rule.profiles or []}
    cmd_result = await relay_signed_command(agent_id, "firewall_edit", params)
    await create_revision(db, rule, diff, current_user.get("sub"), req.reason)
    action = await record_remediation(
        db, agent_id, "firewall_edit", current_user.get("sub"),
        params, cmd_result, req.reason, rule_id=str(rule_id),
    )

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.delete("/{agent_id}/rules/{rule_id}")
async def delete_firewall_rule(
    agent_id: str,
    rule_id: str,
    reason: str = Query("", max_length=1000),
    current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a firewall rule. Admin+ only.

    Also removes any duplicate tracked rows with the same (agent_id, name, direction)
    to clean up historical duplication issues.
    """
    result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.id == rule_id)
        .where(FirewallRule.agent_id == agent_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Tracked rule not found")

    params = {"name": rule.name}
    cmd_result = await relay_signed_command(agent_id, "firewall_delete", params)
    action = await record_remediation(
        db, agent_id, "firewall_delete", current_user.get("sub"),
        params, cmd_result, reason, rule_id=str(rule_id),
    )

    if cmd_result.get("status") == "completed":
        # Find all rules with the same name/direction (includes target + any old duplicates)
        dup_result = await db.execute(
            select(FirewallRule)
            .where(FirewallRule.agent_id == agent_id)
            .where(FirewallRule.name == rule.name)
            .where(FirewallRule.direction == rule.direction)
        )
        dup_ids = [r.id for r in dup_result.scalars().all()]

        if dup_ids:
            # Nullify FK references in remediation_actions (audit trail is kept, just unlinked)
            await db.execute(
                select(RemediationAction)
                .where(RemediationAction.rule_id.in_([str(d) for d in dup_ids]))
            )
            for ra_row in (await db.execute(
                select(RemediationAction).where(RemediationAction.rule_id.in_([str(d) for d in dup_ids]))
            )).scalars().all():
                ra_row.rule_id = None

            # Delete revisions
            for rev in (await db.execute(
                select(FirewallRuleRevision).where(FirewallRuleRevision.rule_id.in_(dup_ids))
            )).scalars().all():
                await db.delete(rev)

            # Delete the rules themselves
            for dup in (await db.execute(
                select(FirewallRule).where(FirewallRule.id.in_(dup_ids))
            )).scalars().all():
                await db.delete(dup)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.post("/{agent_id}/rules/{rule_id}/toggle")
async def toggle_firewall_rule(
    agent_id: str,
    rule_id: str,
    req: FirewallRuleToggleRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Toggle a firewall rule enabled/disabled."""
    result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.id == rule_id)
        .where(FirewallRule.agent_id == agent_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Tracked rule not found")

    params = {"name": rule.name, "enabled": req.enabled}
    cmd_result = await relay_signed_command(agent_id, "firewall_toggle", params)

    if cmd_result.get("status") == "completed":
        old_enabled = rule.enabled
        rule.enabled = req.enabled
        await create_revision(
            db, rule,
            {"enabled": {"old": old_enabled, "new": req.enabled}},
            current_user.get("sub"), req.reason,
        )

    action = await record_remediation(
        db, agent_id, "firewall_toggle", current_user.get("sub"),
        params, cmd_result, req.reason, rule_id=str(rule_id),
    )

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


# ═══════════════════════════════════════════════════════════════════
# Snapshot / Drift Detection
# ═══════════════════════════════════════════════════════════════════


@router.post("/{agent_id}/snapshot")
async def snapshot_firewall(
    agent_id: str,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Take a live snapshot and compare with tracked rules for drift detection."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Get live rules
    cmd_result = await relay_signed_command(agent_id, "firewall_snapshot", {}, timeout_secs=60)
    live_rules = (
        cmd_result.get("data", {}).get("rules", [])
        if cmd_result.get("data")
        else []
    )

    # Get tracked rules
    tracked_result = await db.execute(
        select(FirewallRule).where(FirewallRule.agent_id == agent_id)
    )
    tracked_rules = tracked_result.scalars().all()
    tracked_by_name = {r.name: r for r in tracked_rules}

    live_names = {r.get("Name", r.get("name", "")) for r in live_rules}
    tracked_names = set(tracked_by_name.keys())

    new_rules = [r for r in live_rules if r.get("Name", r.get("name", "")) not in tracked_names]
    missing_rules = [
        {"name": name, "id": str(tracked_by_name[name].id)}
        for name in tracked_names - live_names
    ]

    # Mark drift
    drift_count = len(new_rules) + len(missing_rules)
    for rule in tracked_rules:
        if rule.name in live_names:
            rule.drift_detected = False
        else:
            rule.drift_detected = True

    return {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "live_rule_count": len(live_rules),
        "tracked_rule_count": len(tracked_rules),
        "drift_count": drift_count,
        "new_rules": new_rules[:50],
        "missing_rules": missing_rules[:50],
        "modified_rules": [],
    }


# ═══════════════════════════════════════════════════════════════════
# Policies
# ═══════════════════════════════════════════════════════════════════


@router.get("/policies", response_model=FirewallPolicyListResponse)
async def list_policies(
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List all firewall policies."""
    result = await db.execute(
        select(FirewallPolicy).order_by(desc(FirewallPolicy.created_at))
    )
    policies = result.scalars().all()
    return {"policies": policies, "total": len(policies)}


@router.post("/policies")
async def create_policy(
    req: FirewallPolicyCreate,
    current_user: dict = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new firewall policy. Admin+ only."""
    policy = FirewallPolicy(
        name=req.name,
        description=req.description,
        rules={"rules": [r.model_dump() for r in req.rules]},
        default_inbound_action=req.default_inbound_action,
        default_outbound_action=req.default_outbound_action,
        created_by=current_user.get("sub"),
    )
    db.add(policy)
    await db.flush()
    return {
        "id": str(policy.id),
        "name": policy.name,
        "status": "created",
    }


# ── Helper: import from security for inline role checks ──────────
from app.core.security import ROLE_HIERARCHY

def _role_level(role: str) -> int:
    return ROLE_HIERARCHY.get(role, -1)
