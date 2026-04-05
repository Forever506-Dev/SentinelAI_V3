import os, textwrap

# ── 2. OSINT API Routes ────────────────────────────────────────
path = r"F:\SentinelAI\backend\app\api\routes\osint.py"

content = textwrap.dedent('''\
"""
OSINT Routes — Sandboxed network lookups.

Only exposes: WHOIS, NSLOOKUP, IP Lookup, HTTP Check.
All other outbound traffic is blocked by design.
"""

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import get_current_user
from app.services.osint_tools import (
    whois_lookup,
    nslookup,
    ip_lookup,
    http_check,
)

logger = structlog.get_logger()
router = APIRouter()


# ── Request schemas ─────────────────────────────────────────────

class WhoisRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, description="Domain or IP")

class NslookupRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    record_type: str = Field(default="A", pattern=r"^(A|AAAA|MX|NS|TXT|CNAME|SOA|PTR)$")

class IpLookupRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)

class HttpCheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2000)


# ── Endpoints ───────────────────────────────────────────────────

@router.post("/whois")
async def route_whois(
    payload: WhoisRequest,
    _user: dict = Depends(get_current_user),
) -> dict:
    """WHOIS domain / IP registration lookup."""
    logger.info("OSINT whois", target=payload.target)
    return await whois_lookup(payload.target)


@router.post("/nslookup")
async def route_nslookup(
    payload: NslookupRequest,
    _user: dict = Depends(get_current_user),
) -> dict:
    """DNS record resolution."""
    logger.info("OSINT nslookup", domain=payload.domain, rtype=payload.record_type)
    return await nslookup(payload.domain, payload.record_type)


@router.post("/ip-lookup")
async def route_ip_lookup(
    payload: IpLookupRequest,
    _user: dict = Depends(get_current_user),
) -> dict:
    """IP geolocation + ASN lookup."""
    logger.info("OSINT ip_lookup", ip=payload.ip)
    return await ip_lookup(payload.ip)


@router.post("/http-check")
async def route_http_check(
    payload: HttpCheckRequest,
    _user: dict = Depends(get_current_user),
) -> dict:
    """Website up/down check."""
    logger.info("OSINT http_check", url=payload.url)
    return await http_check(payload.url)
''')

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"OK {path}")
