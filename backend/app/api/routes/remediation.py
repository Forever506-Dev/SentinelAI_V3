"""
Remediation Routes

Firewall rule management and remediation actions for agents.
Uses the agent command relay (Redis) to execute firewall commands
on endpoints and tracks every action in the remediation_actions table.
"""

import asyncio
import json as _json
from datetime import datetime, timezone
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.models.agent import Agent
from app.models.remediation import RemediationAction
from app.services.firewall_service import relay_signed_command

logger = structlog.get_logger()
router = APIRouter()


# ── Redis helper (same pattern as agents.py) ─────────────────────────

_redis_client = None


async def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            from app.core.config import settings
            _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis_client.ping()
        except Exception as e:
            logger.warning("Redis not available for remediation", error=str(e))
            return None
    return _redis_client


# ── Schemas ──────────────────────────────────────────────────────────

class FirewallRuleRequest(BaseModel):
    """Request to add a firewall rule on an agent."""
    name: str = Field("custom-rule", max_length=200)
    direction: str = Field("inbound", pattern=r"^(inbound|outbound)$")
    action: str = Field("block", pattern=r"^(allow|block)$")
    protocol: str = Field("tcp", pattern=r"^(tcp|udp|any|icmp)$")
    port: str = Field("", max_length=100)
    remote_address: str = Field("", max_length=255)
    reason: str = Field("", max_length=1000)


class BlockIPRequest(BaseModel):
    """Quick-block an IP address."""
    ip: str = Field(..., max_length=255)
    direction: str = Field("inbound", pattern=r"^(inbound|outbound)$")
    reason: str = Field("", max_length=1000)


class BlockPortRequest(BaseModel):
    """Quick-block a port."""
    port: str = Field(..., max_length=20)
    protocol: str = Field("tcp", pattern=r"^(tcp|udp)$")
    direction: str = Field("inbound", pattern=r"^(inbound|outbound)$")
    reason: str = Field("", max_length=1000)


class DeleteRuleRequest(BaseModel):
    """Delete a firewall rule."""
    # Windows: name is required. Linux: chain + rule_number or specification.
    name: str = Field("", max_length=255)
    chain: str = Field("INPUT", max_length=20)
    rule_number: int | None = None
    protocol: str = Field("", max_length=10)
    port: str = Field("", max_length=20)
    remote_address: str = Field("", max_length=255)
    action: str = Field("block", max_length=20)
    reason: str = Field("", max_length=1000)


class EditRuleRequest(BaseModel):
    """Edit an existing firewall rule in-place."""
    name: str = Field(..., max_length=255)
    direction: str | None = Field(None, pattern=r"^(inbound|outbound)$")
    action: str | None = Field(None, pattern=r"^(allow|block)$")
    protocol: str | None = Field(None, pattern=r"^(tcp|udp|any|icmp)$")
    port: str | None = Field(None, max_length=100)
    remote_address: str | None = Field(None, max_length=255)
    profiles: list[str] | None = Field(None, description="Windows firewall profiles: domain, private, public")
    reason: str = Field("", max_length=1000)


# ── Helpers ──────────────────────────────────────────────────────────

async def _relay_command(agent_id: str, command: str, parameters: dict, timeout_secs: int = 30) -> dict:
    """Push a command to the agent via Redis and wait for the result."""
    redis = await _get_redis()
    if not redis:
        raise HTTPException(status_code=503, detail="Redis unavailable — cannot relay to agent")

    command_id = str(uuid4())
    cmd_payload = _json.dumps({"command": command, "parameters": parameters})
    await redis.set(f"sentinel:cmd:{command_id}", cmd_payload, ex=300)
    await redis.rpush(f"sentinel:agent:{agent_id}:pending", command_id)

    logger.info("Remediation command queued", command_id=command_id, agent_id=agent_id, command=command)

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


async def _record_action(
    db: AsyncSession,
    agent_id: str,
    action_type: str,
    user_id: str | None,
    params: dict,
    result: dict,
    reason: str = "",
) -> RemediationAction:
    """Record a remediation action in the audit trail."""
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
        applied_at=datetime.now(timezone.utc) if result.get("status") == "completed" else None,
    )
    db.add(action)
    await db.flush()
    return action


# ── Routes ───────────────────────────────────────────────────────────

@router.get("/{agent_id}/rules")
async def get_firewall_rules(
    agent_id: str,
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Fetch the current firewall rules from the agent in real time."""
    # Validate agent exists
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    cmd_result = await _relay_command(agent_id, "firewall_list", {}, timeout_secs=60)

    return {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "os_type": agent.os_type,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
        "rules": cmd_result.get("data", {}).get("rules", []) if cmd_result.get("data") else [],
        "total": cmd_result.get("data", {}).get("total", 0) if cmd_result.get("data") else 0,
    }


@router.post("/{agent_id}/rules")
async def add_firewall_rule(
    agent_id: str,
    req: FirewallRuleRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Add a firewall rule on the agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

    params = {
        "name": req.name,
        "direction": req.direction,
        "action": req.action,
        "protocol": req.protocol,
        "port": req.port,
        "remote_address": req.remote_address,
    }

    cmd_result = await relay_signed_command(agent_id, "firewall_add", params)
    action = await _record_action(db, agent_id, "firewall_add", current_user.get("sub"), params, cmd_result, req.reason)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.post("/{agent_id}/rules/delete")
async def delete_firewall_rule(
    agent_id: str,
    req: DeleteRuleRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Delete a firewall rule from the agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

    params = {
        "name": req.name,
        "chain": req.chain,
        "rule_number": req.rule_number,
        "protocol": req.protocol,
        "port": req.port,
        "remote_address": req.remote_address,
        "action": req.action,
    }

    cmd_result = await relay_signed_command(agent_id, "firewall_delete", params)
    action = await _record_action(db, agent_id, "firewall_delete", current_user.get("sub"), params, cmd_result, req.reason)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.post("/{agent_id}/rules/edit")
async def edit_firewall_rule(
    agent_id: str,
    req: EditRuleRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Edit an existing firewall rule in-place on the agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

    params: dict = {"name": req.name}
    if req.direction is not None:
        params["direction"] = req.direction
    if req.action is not None:
        params["action"] = req.action
    if req.protocol is not None:
        params["protocol"] = req.protocol
    if req.port is not None:
        params["port"] = req.port
    if req.remote_address is not None:
        params["remote_address"] = req.remote_address
    if req.profiles is not None:
        params["profiles"] = req.profiles

    cmd_result = await relay_signed_command(agent_id, "firewall_edit", params)
    action = await _record_action(db, agent_id, "firewall_edit", current_user.get("sub"), params, cmd_result, req.reason)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.post("/{agent_id}/block-ip")
async def block_ip(
    agent_id: str,
    req: BlockIPRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Quick-block an IP address on the agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

    params = {"ip": req.ip, "direction": req.direction}
    cmd_result = await relay_signed_command(agent_id, "firewall_block_ip", params)
    action = await _record_action(db, agent_id, "firewall_block_ip", current_user.get("sub"), params, cmd_result, req.reason)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.post("/{agent_id}/block-port")
async def block_port(
    agent_id: str,
    req: BlockPortRequest,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Quick-block a port on the agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not found")

    params = {"port": req.port, "protocol": req.protocol, "direction": req.direction}
    cmd_result = await relay_signed_command(agent_id, "firewall_block_port", params)
    action = await _record_action(db, agent_id, "firewall_block_port", current_user.get("sub"), params, cmd_result, req.reason)

    return {
        "remediation_id": str(action.id),
        "agent_id": agent_id,
        "status": cmd_result.get("status", "error"),
        "output": cmd_result.get("output", ""),
    }


@router.get("/history")
async def get_remediation_history(
    agent_id: str | None = Query(None),
    action_type: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get remediation action history with optional filters."""
    query = select(RemediationAction).order_by(desc(RemediationAction.created_at))

    if agent_id:
        query = query.where(RemediationAction.agent_id == agent_id)
    if action_type:
        query = query.where(RemediationAction.action_type == action_type)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    actions = result.scalars().all()

    return {
        "actions": [
            {
                "id": str(a.id),
                "agent_id": str(a.agent_id),
                "action_type": a.action_type,
                "rule_name": a.rule_name,
                "direction": a.direction,
                "action": a.action,
                "protocol": a.protocol,
                "port": a.port,
                "remote_address": a.remote_address,
                "status": a.status,
                "result_output": a.result_output,
                "error_message": a.error_message,
                "reason": a.reason,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "applied_at": a.applied_at.isoformat() if a.applied_at else None,
            }
            for a in actions
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
