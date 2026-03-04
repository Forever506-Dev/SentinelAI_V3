"""
Start backend, register/login, test all OSINT + Investigation endpoints.
Backend runs as a detached subprocess that stays alive after this script ends.
"""
import subprocess
import sys
import time
import json
import os

import httpx

# Test user credentials — override via environment variables
_test_password = os.environ.get("SENTINEL_TEST_PASSWORD", "Test!2026x")
_backend_dir = os.environ.get(
    "SENTINEL_BACKEND_DIR",
    os.path.join(os.path.dirname(__file__), "backend"),
)

# --- Start backend as detached subprocess ---
CREATE_NEW_PROCESS_GROUP = 0x00000200
DETACHED_PROCESS = 0x00000008

backend = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8080"],
    cwd=_backend_dir,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
)
print(f"Backend started (PID={backend.pid}), waiting for ready...")

BASE = "http://127.0.0.1:8080"
API = f"{BASE}/api/v1"
client = httpx.Client(timeout=30.0)

for i in range(30):
    try:
        r = client.get(f"{BASE}/health")
        if r.status_code == 200:
            print(f"  Ready after {i+1}s")
            break
    except Exception:
        pass
    time.sleep(1)
else:
    print("  FAIL: Backend not ready after 30s")
    sys.exit(1)

# --- Register a test user (idempotent) ---
print("\n[REGISTER]")
r = client.post(f"{API}/auth/register", json={
    "username": "testanalyst",
    "email": "analyst@sentinelai.dev",
    "password": _test_password,
    "full_name": "Test Analyst",
})
if r.status_code == 201:
    print(f"  New user created")
elif r.status_code == 409:
    print(f"  User already exists (OK)")
else:
    print(f"  Register: {r.status_code} {r.text[:300]}")

# --- Login ---
print("\n[LOGIN]")
r = client.post(f"{API}/auth/login", json={
    "username": "testanalyst",
    "password": _test_password,
})
print(f"  Status: {r.status_code}")
if r.status_code != 200:
    print(f"  Body: {r.text[:500]}")
    sys.exit(1)
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"  Token: {token[:30]}...")

# =====================================================================
# OSINT Tests
# =====================================================================

print("\n" + "=" * 60)
print("OSINT NSLOOKUP (google.com A)")
print("=" * 60)
r = client.post(f"{API}/osint/nslookup", json={"domain": "google.com", "record_type": "A"}, headers=headers)
print(f"  HTTP {r.status_code}")
print(f"  {json.dumps(r.json(), indent=2)[:500]}")

print("\n" + "=" * 60)
print("OSINT IP LOOKUP (8.8.8.8)")
print("=" * 60)
r = client.post(f"{API}/osint/ip-lookup", json={"ip": "8.8.8.8"}, headers=headers)
print(f"  HTTP {r.status_code}")
data = r.json()
print(f"  Country: {data.get('country')}, City: {data.get('city')}, ISP: {data.get('isp')}")
print(f"  Org: {data.get('org')}, AS: {data.get('as')}")

print("\n" + "=" * 60)
print("OSINT HTTP CHECK (google.com)")
print("=" * 60)
r = client.post(f"{API}/osint/http-check", json={"url": "https://google.com"}, headers=headers)
print(f"  HTTP {r.status_code}")
data = r.json()
print(f"  Site status: {data.get('status')}")
print(f"  Status code: {data.get('status_code')}")
print(f"  Response time: {data.get('response_time_ms')}ms")
print(f"  Final URL: {data.get('final_url')}")

print("\n" + "=" * 60)
print("OSINT WHOIS (google.com)")
print("=" * 60)
r = client.post(f"{API}/osint/whois", json={"target": "google.com"}, headers=headers)
print(f"  HTTP {r.status_code}")
data = r.json()
if "data" in data:
    print(f"  Registrar: {data['data'].get('registrar', 'N/A')}")
    print(f"  Org: {data['data'].get('org', 'N/A')}")
    print(f"  Created: {data['data'].get('creation_date', 'N/A')}")
    print(f"  Expires: {data['data'].get('expiration_date', 'N/A')}")
elif "raw" in data:
    print(f"  Raw (first 300): {data['raw'][:300]}")
elif "error" in data:
    print(f"  Error: {data['error']}")

# =====================================================================
# Investigation Test (LLM)
# =====================================================================

print("\n" + "=" * 60)
print("INVESTIGATION: Vulnerability report for DESKTOP-U52HOUK")
print("(Calls Ollama LLM - may take 30-120s...)")
print("=" * 60)
try:
    r = client.post(
        f"{API}/analysis/investigate",
        json={"query": "Give me a vulnerability report for DESKTOP-U52HOUK", "context": {}},
        headers=headers,
        timeout=180.0,
    )
    print(f"  HTTP {r.status_code}")
    data = r.json()
    print(f"  Status: {data.get('status')}")
    analysis = str(data.get("analysis", ""))
    print(f"  Analysis (first 1000 chars):")
    print(f"    {analysis[:1000]}")
    print(f"  Confidence: {data.get('confidence')}")
    recs = data.get("recommendations", [])
    print(f"  Recommendations ({len(recs)}):")
    for rec in recs[:5]:
        print(f"    - {rec}")
    techniques = data.get("related_techniques", [])
    print(f"  MITRE Techniques: {techniques[:5]}")
    tools = data.get("tools_used", [])
    print(f"  OSINT Tools Used: {len(tools)}")
    for t in tools[:5]:
        print(f"    - {t.get('tool')}({json.dumps(t.get('args', {}))})")
except httpx.ReadTimeout:
    print("  TIMEOUT after 180s (LLM may be slow)")
except Exception as e:
    print(f"  Error: {e}")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETE")
print(f"Backend PID: {backend.pid} (still running)")
print(f"To stop: taskkill /PID {backend.pid} /F")
print("=" * 60)
