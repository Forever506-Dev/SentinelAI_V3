import os, textwrap

# ── 1. OSINT Tools Service ────────────────────────────────────
path = r"F:\SentinelAI\backend\app\services\osint_tools.py"

content = textwrap.dedent('''\
"""
OSINT Tools Service  —  Sandboxed Network Lookups

Provides ONLY these specific, controlled internet lookups:
  1. WHOIS   — domain / IP registration data
  2. NSLOOKUP — DNS record resolution
  3. IP Lookup — geolocation + ASN via ip-api.com (free, no key)
  4. HTTP Check — is a website up? (HEAD request, 10 s timeout)

No other outbound traffic is initiated.  Every function is
self-contained and returns a plain dict.
"""

import asyncio
import socket
import subprocess
import sys
from datetime import datetime, timezone

import httpx
import structlog

logger = structlog.get_logger()

# ── Allowed IP-lookup provider (free, no API key) ──────────────
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"


# ─────────────────────────────────────────────────────────────────
#  1.  WHOIS
# ─────────────────────────────────────────────────────────────────
async def whois_lookup(target: str) -> dict:
    """
    Run a WHOIS lookup on a domain or IP address.
    Uses the system `whois` command or the python-whois library.
    """
    target = target.strip().lower()
    if not target:
        return {"error": "Empty target"}

    # Try python-whois first
    try:
        import whois as python_whois
        w = python_whois.whois(target)
        data = {}
        for key in (
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "org", "address", "city", "state", "country",
            "registrant_postal_code", "dnssec",
        ):
            val = getattr(w, key, None)
            if val is not None:
                if isinstance(val, list):
                    val = [str(v) for v in val]
                elif isinstance(val, datetime):
                    val = val.isoformat()
                else:
                    val = str(val)
                data[key] = val
        return {"target": target, "tool": "whois", "data": data}
    except ImportError:
        pass
    except Exception as e:
        logger.debug("python-whois failed, falling back to CLI", error=str(e))

    # Fallback to CLI whois
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode(errors="replace").strip()
        if not output:
            output = stderr.decode(errors="replace").strip()
        return {"target": target, "tool": "whois", "raw": output[:5000]}
    except FileNotFoundError:
        # Windows: try PowerShell
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-NoProfile", "-Command",
                f"(Invoke-WebRequest -Uri 'https://whois.iana.org/{target}' -UseBasicParsing -TimeoutSec 10).Content",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            return {"target": target, "tool": "whois", "raw": stdout.decode(errors="replace").strip()[:5000]}
        except Exception as e2:
            return {"target": target, "tool": "whois", "error": f"whois not available: {e2}"}
    except Exception as e:
        return {"target": target, "tool": "whois", "error": str(e)}


# ─────────────────────────────────────────────────────────────────
#  2.  NSLOOKUP  (DNS)
# ─────────────────────────────────────────────────────────────────
async def nslookup(domain: str, record_type: str = "A") -> dict:
    """
    Resolve DNS records for a domain.
    Supports: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
    """
    domain = domain.strip().lower()
    record_type = record_type.strip().upper()
    allowed_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"}
    if record_type not in allowed_types:
        return {"error": f"Record type must be one of {allowed_types}"}
    if not domain:
        return {"error": "Empty domain"}

    # Try dnspython first
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        answers = resolver.resolve(domain, record_type)
        records = [str(rdata) for rdata in answers]
        return {
            "domain": domain,
            "record_type": record_type,
            "tool": "nslookup",
            "records": records,
            "ttl": answers.rrset.ttl if answers.rrset else None,
        }
    except ImportError:
        pass
    except Exception as e:
        # dnspython installed but query failed
        return {
            "domain": domain,
            "record_type": record_type,
            "tool": "nslookup",
            "records": [],
            "error": str(e),
        }

    # Fallback to nslookup CLI
    try:
        proc = await asyncio.create_subprocess_exec(
            "nslookup", f"-type={record_type}", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode(errors="replace").strip()
        return {
            "domain": domain,
            "record_type": record_type,
            "tool": "nslookup",
            "raw": output[:3000],
        }
    except Exception as e:
        return {"domain": domain, "record_type": record_type, "tool": "nslookup", "error": str(e)}


# ─────────────────────────────────────────────────────────────────
#  3.  IP LOOKUP  (Geolocation + ASN)
# ─────────────────────────────────────────────────────────────────
async def ip_lookup(ip: str) -> dict:
    """
    Geolocate an IP address and return ASN / ISP / org data.
    Uses ip-api.com (free tier, no API key, 45 req/min).
    """
    ip = ip.strip()
    if not ip:
        return {"error": "Empty IP"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(IP_API_URL.format(ip=ip))
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "fail":
                return {"ip": ip, "tool": "ip_lookup", "error": data.get("message", "lookup failed")}
            data["tool"] = "ip_lookup"
            return data
    except Exception as e:
        return {"ip": ip, "tool": "ip_lookup", "error": str(e)}


# ─────────────────────────────────────────────────────────────────
#  4.  HTTP CHECK  (Website Up/Down)
# ─────────────────────────────────────────────────────────────────
async def http_check(url: str) -> dict:
    """
    Check if a URL is reachable.  Issues a HEAD (then GET fallback)
    with a 10-second timeout.  No body is read.
    """
    url = url.strip()
    if not url:
        return {"error": "Empty URL"}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result: dict = {"url": url, "tool": "http_check"}
    try:
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            import time
            t0 = time.monotonic()
            try:
                resp = await client.head(url)
            except httpx.HTTPStatusError:
                resp = await client.get(url)
            elapsed_ms = round((time.monotonic() - t0) * 1000)
            result.update({
                "status": "up",
                "status_code": resp.status_code,
                "response_time_ms": elapsed_ms,
                "headers": {
                    "server": resp.headers.get("server", ""),
                    "content-type": resp.headers.get("content-type", ""),
                    "x-powered-by": resp.headers.get("x-powered-by", ""),
                },
                "final_url": str(resp.url),
                "tls": url.startswith("https://"),
            })
    except httpx.ConnectError:
        result.update({"status": "down", "error": "Connection refused or DNS failure"})
    except httpx.ConnectTimeout:
        result.update({"status": "down", "error": "Connection timed out (10 s)"})
    except httpx.ReadTimeout:
        result.update({"status": "down", "error": "Read timed out (10 s)"})
    except Exception as e:
        result.update({"status": "down", "error": str(e)})
    return result


# ─────────────────────────────────────────────────────────────────
#  Tool dispatcher  (used by the LLM tool-call loop)
# ─────────────────────────────────────────────────────────────────
AVAILABLE_TOOLS = {
    "whois": whois_lookup,
    "nslookup": nslookup,
    "ip_lookup": ip_lookup,
    "http_check": http_check,
}

TOOL_DESCRIPTIONS = """Available OSINT tools you may invoke (respond with tool_calls array):
1. whois(target)         — WHOIS registration data for a domain or IP
2. nslookup(domain, record_type="A")  — DNS record lookup (A/AAAA/MX/NS/TXT/CNAME/SOA/PTR)
3. ip_lookup(ip)         — Geolocation, ASN, ISP for an IP address
4. http_check(url)       — Check if a website is reachable (up/down, status code, response time)
"""


async def execute_tool(tool_name: str, args: dict) -> dict:
    """Execute a single OSINT tool by name with args dict."""
    fn = AVAILABLE_TOOLS.get(tool_name)
    if not fn:
        return {"error": f"Unknown tool: {tool_name}. Available: {list(AVAILABLE_TOOLS.keys())}"}
    try:
        return await fn(**args)
    except TypeError as e:
        return {"error": f"Invalid arguments for {tool_name}: {e}"}
    except Exception as e:
        return {"error": f"Tool {tool_name} failed: {e}"}
''')

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"OK {path}")
