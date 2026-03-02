"""
Firewall Service

Business logic for firewall rule management:
- HMAC-signed command relay to agents
- Rule CRUD with revision tracking
- Drift detection (live vs tracked)
- Self-block prevention
- Approval workflow integration
"""

import asyncio
import json as _json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import sign_command, generate_nonce
from app.models.agent import Agent
from app.models.firewall import FirewallRule, FirewallRuleRevision, FirewallPolicy
from app.models.remediation import RemediationAction
from app.models.approval import RemediationApproval

logger = structlog.get_logger()

# ── Redis helper ─────────────────────────────────────────────────────

_redis_client = None


async def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis_client.ping()
        except Exception as e:
            logger.warning("Redis not available for firewall service", error=str(e))
            return None
    return _redis_client


# ── Self-Block Prevention ────────────────────────────────────────────

SAFE_ADDRESSES = {"127.0.0.1", "::1", "localhost"}


def check_self_block(remote_address: str, backend_url: str = "") -> bool:
    """
    Return True if the rule would block communication with the backend
    or the agent itself (self-block prevention).
    """
    if not remote_address or remote_address.lower() in ("any", ""):
        return False

    # Extract backend IP from URL
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(backend_url or settings.CORS_ORIGINS[0])
        backend_host = parsed.hostname or ""
    except Exception:
        backend_host = ""

    dangerous = SAFE_ADDRESSES | {backend_host}
    # Also add all CORS origins' hosts
    for origin in settings.CORS_ORIGINS:
        try:
            parsed = urllib.parse.urlparse(origin)
            if parsed.hostname:
                dangerous.add(parsed.hostname)
        except Exception:
            pass

    return remote_address.strip().lower() in {a.lower() for a in dangerous if a}


# ── Signed Command Relay ─────────────────────────────────────────────

async def relay_signed_command(
    agent_id: str,
    command: str,
    parameters: dict,
    timeout_secs: int = 30,
) -> dict:
    """
    Relay a command to the agent via Redis, signed with HMAC-SHA256.
    Uses the per-agent HMAC key stored in the database.
    """
    redis = await _get_redis()
    if not redis:
        return {"status": "error", "output": "Redis unavailable — cannot relay to agent"}

    # Fetch the per-agent HMAC key from the DB
    from app.core.database import async_session_factory
    agent_hmac_key: str | None = None
    try:
        async with async_session_factory() as db:
            result = await db.execute(select(Agent).where(Agent.id == agent_id))
            agent = result.scalar_one_or_none()
            if agent and agent.hmac_key:
                agent_hmac_key = agent.hmac_key
    except Exception as e:
        logger.warning("Failed to fetch agent HMAC key", error=str(e), agent_id=agent_id)

    if not agent_hmac_key:
        logger.warning("No per-agent HMAC key found, falling back to global key", agent_id=agent_id)
        agent_hmac_key = settings.REMEDIATION_HMAC_KEY

    command_id = str(uuid4())
    nonce = generate_nonce()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build enriched parameters (what the agent will receive and verify)
    enriched_params = dict(parameters)
    enriched_params["_nonce"] = nonce
    enriched_params["_timestamp"] = timestamp
    enriched_params["_command_id"] = command_id

    # Sign the enriched params (excluding _signature which will be added next).
    # The agent verifies by serialising all param keys except _signature.
    signature = sign_command(enriched_params, hmac_key=agent_hmac_key)

    enriched_params["_signature"] = signature

    cmd_payload = _json.dumps({"command": command, "parameters": enriched_params})
    await redis.set(f"sentinel:cmd:{command_id}", cmd_payload, ex=300)
    await redis.rpush(f"sentinel:agent:{agent_id}:pending", command_id)

    logger.info(
        "Signed firewall command queued",
        command_id=command_id,
        agent_id=agent_id,
        command=command,
    )

    # Poll for result
    result_key = f"sentinel:cmd:{command_id}:result"
    for _ in range(timeout_secs * 2):
        result_data = await redis.get(result_key)
        if result_data:
            parsed = _json.loads(result_data)
            await redis.delete(result_key)
            await redis.delete(f"sentinel:cmd:{command_id}")
            return parsed
        await asyncio.sleep(0.5)

    await redis.delete(f"sentinel:cmd:{command_id}")
    return {"status": "timeout", "output": "Agent did not respond in time."}


# ── Record Action with Audit ────────────────────────────────────────

async def record_remediation(
    db: AsyncSession,
    agent_id: str,
    action_type: str,
    user_id: str | None,
    params: dict,
    result: dict,
    reason: str = "",
    rule_id: str | None = None,
    approval_id: str | None = None,
    rollback_of: str | None = None,
    signature: str | None = None,
) -> RemediationAction:
    """Record a remediation action with full audit trail."""
    action = RemediationAction(
        agent_id=agent_id,
        action_type=action_type,
        rule_name=params.get("name", params.get("ip", params.get("port", ""))),
        direction=params.get("direction"),
        action=params.get("action"),
        protocol=params.get("protocol"),
        port=str(params.get("port", "")),
        remote_address=params.get("remote_address", params.get("ip", "")),
        parameters=params,
        status="applied" if result.get("status") == "completed" else "failed",
        result_output=result.get("output", ""),
        error_message=result.get("output", "") if result.get("status") != "completed" else None,
        initiated_by=user_id,
        reason=reason,
        rule_id=rule_id,
        approval_id=approval_id,
        rollback_of=rollback_of,
        command_signature=signature,
        applied_at=datetime.now(timezone.utc) if result.get("status") == "completed" else None,
    )
    db.add(action)
    await db.flush()
    return action


# ── Create Approval Request ──────────────────────────────────────────

async def create_approval_request(
    db: AsyncSession,
    remediation_id: str,
    requested_by: str,
    reason: str = "",
) -> RemediationApproval:
    """Create a pending approval request for a remediation action."""
    approval = RemediationApproval(
        remediation_id=remediation_id,
        requested_by=requested_by,
        request_reason=reason,
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.APPROVAL_EXPIRY_HOURS),
    )
    db.add(approval)
    await db.flush()
    return approval


# ── Track Rule in DB ─────────────────────────────────────────────────

async def track_rule(
    db: AsyncSession,
    agent_id: str,
    rule_data: dict,
    user_id: str | None = None,
    policy_id: str | None = None,
) -> FirewallRule:
    """Track a firewall rule in the database after it's applied to an agent.

    Uses upsert semantics: if a rule with the same (agent_id, name, direction)
    already exists, it is updated in place rather than creating a duplicate row.
    """
    # Normalise profiles: accept list or comma-separated string
    raw_profiles = rule_data.get("profiles", [])
    if isinstance(raw_profiles, str):
        raw_profiles = [p.strip().lower() for p in raw_profiles.split(",") if p.strip()]
    elif not raw_profiles:
        # Fall back to scalar profile field
        scalar = rule_data.get("profile", "any")
        if scalar and scalar.lower() != "any":
            raw_profiles = [p.strip().lower() for p in scalar.split(",") if p.strip()]
        else:
            raw_profiles = []

    rule_name = rule_data.get("name", "unknown")
    direction = rule_data.get("direction", "inbound")

    # ── Check for existing rule with same (agent_id, name, direction) ──
    existing_result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.agent_id == agent_id)
        .where(FirewallRule.name == rule_name)
        .where(FirewallRule.direction == direction)
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        # Update existing rule in place
        logger.info("Updating existing tracked rule (dedup)",
                     rule_id=str(existing.id), name=rule_name, agent_id=agent_id)
        existing.action = rule_data.get("action", existing.action)
        existing.protocol = rule_data.get("protocol", existing.protocol)
        existing.local_port = rule_data.get("local_port", existing.local_port)
        existing.remote_port = rule_data.get("remote_port", existing.remote_port)
        existing.local_address = rule_data.get("local_address", existing.local_address)
        existing.remote_address = rule_data.get("remote_address", existing.remote_address)
        existing.enabled = rule_data.get("enabled", existing.enabled)
        existing.profile = rule_data.get("profile", existing.profile)
        existing.profiles = raw_profiles
        existing.synced_at = datetime.now(timezone.utc)
        existing.updated_at = datetime.now(timezone.utc)
        if policy_id:
            existing.policy_id = policy_id
        await db.flush()
        return existing

    # ── Create new rule ──
    rule = FirewallRule(
        agent_id=agent_id,
        name=rule_name,
        direction=direction,
        action=rule_data.get("action", "block"),
        protocol=rule_data.get("protocol", "any"),
        local_port=rule_data.get("local_port", "any"),
        remote_port=rule_data.get("remote_port", "any"),
        local_address=rule_data.get("local_address", "any"),
        remote_address=rule_data.get("remote_address", "any"),
        enabled=rule_data.get("enabled", True),
        profile=rule_data.get("profile", "any"),
        profiles=raw_profiles,
        policy_id=policy_id,
        synced_at=datetime.now(timezone.utc),
        created_by=user_id,
    )
    db.add(rule)
    await db.flush()

    # Create initial revision
    revision = FirewallRuleRevision(
        rule_id=rule.id,
        version=1,
        snapshot=rule_data,
        changed_by=user_id,
        change_reason="Initial creation",
    )
    db.add(revision)
    await db.flush()

    return rule


# ── Create Rule Revision ─────────────────────────────────────────────

async def create_revision(
    db: AsyncSession,
    rule: FirewallRule,
    diff: dict,
    user_id: str | None = None,
    reason: str = "",
) -> FirewallRuleRevision:
    """Create a new revision for a firewall rule after changes."""
    rule.current_version += 1
    revision = FirewallRuleRevision(
        rule_id=rule.id,
        version=rule.current_version,
        diff=diff,
        snapshot={
            "name": rule.name,
            "direction": rule.direction,
            "action": rule.action,
            "protocol": rule.protocol,
            "local_port": rule.local_port,
            "remote_port": rule.remote_port,
            "local_address": rule.local_address,
            "remote_address": rule.remote_address,
            "enabled": rule.enabled,
            "profile": rule.profile,
            "profiles": rule.profiles or [],
        },
        changed_by=user_id,
        change_reason=reason,
    )
    db.add(revision)
    await db.flush()
    return revision
