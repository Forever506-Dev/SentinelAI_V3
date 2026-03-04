"""Quick test script for the auth endpoints."""
import urllib.request
import urllib.error
import json
import os
import sys

BASE = "http://localhost:8080/api/v1/auth"

_admin_password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
if not _admin_password:
    print("Error: SENTINEL_ADMIN_PASSWORD environment variable is not set.")
    print("Usage:  SENTINEL_ADMIN_PASSWORD='...' python test_auth.py")
    sys.exit(1)

def post(path, data):
    url = f"{BASE}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        print(f"  ✅ {resp.status} OK")
        return result
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  ❌ {e.code}: {err}")
        return None

def get(path, token):
    url = f"{BASE}{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        print(f"  ✅ {resp.status} OK")
        return result
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  ❌ {e.code}: {err}")
        return None

print("=" * 60)
print("TEST 1: Login with admin / $SENTINEL_ADMIN_PASSWORD")
print("=" * 60)
result = post("/login", {"username": "admin", "password": _admin_password})
if result:
    print(f"  access_token: {result.get('access_token', 'N/A')[:40]}...")
    print(f"  requires_2fa: {result.get('requires_2fa')}")
    print(f"  token_type: {result.get('token_type')}")
    token = result.get("access_token")
else:
    print("  Login failed, aborting remaining tests.")
    sys.exit(1)

print()
print("=" * 60)
print("TEST 2: GET /me with token")
print("=" * 60)
me = get("/me", token)
if me:
    print(f"  username: {me.get('username')}")
    print(f"  email: {me.get('email')}")
    print(f"  role: {me.get('role')}")
    print(f"  totp_enabled: {me.get('totp_enabled')}")

print()
print("=" * 60)
print("TEST 3: Login with wrong password")
print("=" * 60)
post("/login", {"username": "admin", "password": "wrongpassword"})

print()
print("=" * 60)
print("TEST 4: Forgot password")
print("=" * 60)
result = post("/forgot-password", {"email": "admin@sentinelai.dev"})
if result:
    print(f"  message: {result.get('message')}")

print()
print("=" * 60)
print("TEST 5: Change password (authenticated)")
print("=" * 60)
url = f"{BASE}/change-password"
body = json.dumps({"current_password": _admin_password, "new_password": _admin_password}).encode()
req = urllib.request.Request(url, data=body, headers={
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}"
})
try:
    resp = urllib.request.urlopen(req)
    print(f"  ✅ {resp.status}: {json.loads(resp.read())}")
except urllib.error.HTTPError as e:
    print(f"  ❌ {e.code}: {e.read().decode()}")

print()
print("=" * 60)
print("ALL TESTS COMPLETE")
print("=" * 60)
