import os, textwrap

# ── 3. Updated Analysis Routes with agent enrichment ──────────
path = r"F:\SentinelAI\backend\app\api\routes\analysis.py"

content = textwrap.dedent('''\
"""
AI Analysis Routes

Natural language threat investigation with automatic agent/telemetry
enrichment and OSINT tool-calling via LLM.
"""

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.core.database import get_session
from app.models.agent import Agent
from app.models.alert import Alert
from app.models.telemetry import TelemetryEvent

logger = structlog.get_logger()
router = APIRouter()


class InvestigationQuery(BaseModel):
    query: str = Field(..., min_length=3, max_length=4000)
    context: dict = Field(default_factory=dict)


class ThreatLookupRequest(BaseModel):
    indicator_type: str = Field(..., pattern=r"^(ip|domain|hash_sha256|hash_md5|cve|url|email)$")
    indicator_value: str = Field(..., min_length=1, max_length=500)


# ─────────────────────────────────────────────────────────────────
# Helper: auto-enrich context from the database
# ─────────────────────────────────────────────────────────────────

async def _enrich_context(query: str, context: dict, db: AsyncSession) -> dict:
    """
    Detect agent hostnames / IPs in the query and auto-load their
    profile, recent alerts, and recent telemetry so the LLM has
    real data to work with.
    """
    enriched = dict(context)

    # ── 1.  Find agent references in the query ──────────────────
    agents_result = await db.execute(select(Agent).where(Agent.status != "decommissioned"))
    all_agents = agents_result.scalars().all()

    matched_agents: list[Agent] = []
    query_lower = query.lower()
    for agent in all_agents:
        if (
            agent.hostname.lower() in query_lower
            or (agent.internal_ip and agent.internal_ip in query)
            or (agent.external_ip and agent.external_ip in query)
            or str(agent.id) in query
        ):
            matched_agents.append(agent)

    # If no specific agent matched but user says "my endpoint" / "my system"
    # and there is exactly one online agent, use that
    if not matched_agents:
        vague_terms = ["my endpoint", "my system", "my machine", "my computer", "my desktop", "my server", "this system", "this machine"]
        if any(term in query_lower for term in vague_terms):
            online = [a for a in all_agents if a.status == "online"]
            if len(online) == 1:
                matched_agents = online

    if not matched_agents:
        # Still provide a summary of all agents
        enriched["available_agents"] = [
            {"hostname": a.hostname, "os": f"{a.os_type} {a.os_version}", "status": a.status, "ip": a.internal_ip}
            for a in all_agents[:10]
        ]
        return enriched

    # ── 2.  Enrich each matched agent ───────────────────────────
    agent_profiles = []
    for agent in matched_agents[:3]:  # cap at 3
        profile: dict = {
            "agent_id": str(agent.id),
            "hostname": agent.hostname,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "architecture": agent.architecture,
            "internal_ip": agent.internal_ip,
            "external_ip": agent.external_ip,
            "status": agent.status,
            "is_isolated": agent.is_isolated,
            "cpu_usage": agent.cpu_usage,
            "memory_usage": agent.memory_usage,
            "disk_usage": agent.disk_usage,
            "uptime_seconds": agent.uptime_seconds,
            "agent_version": agent.agent_version,
            "last_heartbeat": str(agent.last_heartbeat) if agent.last_heartbeat else None,
            "registered_at": str(agent.registered_at),
            "tags": agent.tags,
            "installed_software": agent.installed_software,
        }

        # ── Recent alerts for this agent ────────────────────────
        alerts_q = await db.execute(
            select(Alert)
            .where(Alert.agent_id == str(agent.id))
            .order_by(desc(Alert.detected_at))
            .limit(15)
        )
        recent_alerts = alerts_q.scalars().all()
        profile["recent_alerts"] = [
            {
                "title": a.title,
                "severity": a.severity,
                "confidence": a.confidence,
                "status": a.status,
                "detection_source": a.detection_source,
                "mitre_tactics": a.mitre_tactics,
                "mitre_techniques": a.mitre_techniques,
                "description": (a.description or "")[:300],
                "detected_at": str(a.detected_at),
            }
            for a in recent_alerts
        ]

        # ── Recent telemetry  ──────────────────────────────────
        telem_q = await db.execute(
            select(TelemetryEvent)
            .where(TelemetryEvent.agent_id == str(agent.id))
            .order_by(desc(TelemetryEvent.received_at))
            .limit(30)
        )
        recent_telemetry = telem_q.scalars().all()
        profile["recent_telemetry_summary"] = {
            "total_events": len(recent_telemetry),
            "event_types": {},
            "processes_seen": [],
            "network_connections": [],
            "suspicious_flags": [],
        }
        seen_procs = set()
        for ev in recent_telemetry:
            etype = ev.event_type or "unknown"
            profile["recent_telemetry_summary"]["event_types"][etype] = (
                profile["recent_telemetry_summary"]["event_types"].get(etype, 0) + 1
            )
            if ev.process_name and ev.process_name not in seen_procs:
                seen_procs.add(ev.process_name)
                profile["recent_telemetry_summary"]["processes_seen"].append({
                    "name": ev.process_name,
                    "pid": ev.process_id,
                    "cmd": (ev.command_line or "")[:200],
                })
            if ev.dest_ip:
                profile["recent_telemetry_summary"]["network_connections"].append({
                    "dest_ip": ev.dest_ip,
                    "dest_port": ev.dest_port,
                    "protocol": ev.protocol,
                    "dns_query": ev.dns_query,
                })

        # ── Alert count summary ─────────────────────────────────
        count_q = await db.execute(
            select(
                Alert.severity,
                func.count(Alert.id).label("cnt"),
            )
            .where(Alert.agent_id == str(agent.id))
            .group_by(Alert.severity)
        )
        profile["alert_counts_by_severity"] = {
            row.severity: row.cnt for row in count_q
        }

        agent_profiles.append(profile)

    enriched["matched_agents"] = agent_profiles
    return enriched


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@router.post("/investigate")
async def investigate(
    payload: InvestigationQuery,
    _current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    """AI-powered threat investigation with automatic context enrichment."""
    from app.services.llm_engine import LLMEngine

    # ── Auto-enrich context ────────────────────────────────────
    enriched_context = await _enrich_context(payload.query, payload.context, db)

    engine = LLMEngine()

    try:
        result = await engine.investigate(
            query=payload.query,
            context=enriched_context,
        )
        return {
            "status": "completed",
            "query": payload.query,
            "analysis": result.get("analysis", ""),
            "confidence": result.get("confidence", 0),
            "recommendations": result.get("recommendations", []),
            "related_techniques": result.get("mitre_techniques", []),
            "sources": result.get("sources", []),
            "tools_used": result.get("tools_used", []),
        }
    except Exception as e:
        logger.error("Investigation failed", query=payload.query[:100], error=str(e))
        return {
            "status": "error",
            "query": payload.query,
            "analysis": f"Investigation failed: {e}",
            "confidence": 0,
            "recommendations": [],
            "related_techniques": [],
            "sources": [],
        }


@router.post("/threat-lookup")
async def threat_lookup(
    payload: ThreatLookupRequest,
    _current_user: dict = Depends(get_current_user),
) -> dict:
    """Look up a threat indicator across multiple intelligence sources."""
    from app.services.threat_analyzer import ThreatAnalyzer

    analyzer = ThreatAnalyzer()
    result = await analyzer.lookup_indicator(
        indicator_type=payload.indicator_type,
        indicator_value=payload.indicator_value,
    )
    return {
        "indicator_type": payload.indicator_type,
        "indicator_value": payload.indicator_value,
        "threat_level": result["threat_level"],
        "sources": result["sources"],
        "details": result["details"],
        "recommendations": result["recommendations"],
    }
''')

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"OK {path}")
