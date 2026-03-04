"""Start server, run auth tests, stop server."""
import subprocess
import sys
import time
import urllib.request
import urllib.error
import json
import os

_admin_password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
if not _admin_password:
    print("Error: SENTINEL_ADMIN_PASSWORD environment variable is not set.")
    print("Usage:  SENTINEL_ADMIN_PASSWORD='...' python test_auth_full.py")
    sys.exit(1)

PYTHON = sys.executable
BACKEND_DIR = os.environ.get("SENTINEL_BACKEND_DIR", os.path.join(os.path.dirname(__file__), "backend"))
BASE = "http://localhost:8080/api/v1/auth"

# Start the server
print("[*] Starting backend server...")
env = os.environ.copy()
proc = subprocess.Popen(
    [PYTHON, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "error"],
    cwd=BACKEND_DIR,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=env,
)

# Wait for server to be ready
print("[*] Waiting for server to be ready...")
for i in range(15):
    time.sleep(1)
    try:
        urllib.request.urlopen("http://localhost:8080/api/v1/auth/me")
        print(f"[+] Server ready after {i+1}s")
        break
    except urllib.error.HTTPError:
        # 401 is expected for /me without token — means server is up
        print(f"[+] Server ready after {i+1}s (got 401, server is up)")
        break
    except Exception:
        pass
else:
    print("[-] Server failed to start in 15s")
    proc.kill()
    out, err = proc.communicate()
    print("STDOUT:", out.decode()[-2000:])
    print("STDERR:", err.decode()[-2000:])
    sys.exit(1)

def post(path, data, token=None):
    url = f"{BASE}{path}"
    body = json.dumps(data).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        print(f"  ✅ {resp.status} OK")
        return result
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"  ❌ {e.code}: {err_body[:200]}")
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
        err_body = e.read().decode()
        print(f"  ❌ {e.code}: {err_body[:200]}")
        return None

try:
    print()
    print("=" * 60)
    print("TEST 1: Login with admin / $SENTINEL_ADMIN_PASSWORD")
    print("=" * 60)
    result = post("/login", {"username": "admin", "password": _admin_password})
    if result:
        print(f"  access_token: {result.get('access_token', 'N/A')[:50]}...")
        print(f"  requires_2fa: {result.get('requires_2fa')}")
        print(f"  token_type: {result.get('token_type')}")
        token = result.get("access_token")
    else:
        print("  FAILED - aborting")
        sys.exit(1)

    print()
    print("=" * 60)
    print("TEST 2: GET /me")
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
    print("TEST 4: Forgot password (should always return 200)")
    print("=" * 60)
    result = post("/forgot-password", {"email": "admin@sentinelai.dev"})
    if result:
        print(f"  message: {result.get('message')}")

    print()
    print("=" * 60)
    print("TEST 5: Change password (authenticated)")
    print("=" * 60)
    result = post("/change-password", {"current_password": _admin_password, "new_password": _admin_password}, token=token)
    if result:
        print(f"  message: {result.get('message')}")

    print()
    print("=" * 60)
    print("TEST 6: 2FA Setup")
    print("=" * 60)
    setup = post("/2fa/setup", {}, token=token)
    if setup:
        print(f"  secret: {setup.get('secret', 'N/A')[:10]}...")
        print(f"  provisioning_uri present: {bool(setup.get('provisioning_uri'))}")
        print(f"  qr_code_base64 present: {bool(setup.get('qr_code_base64'))}")

    print()
    print("=" * 60)
    print("ALL TESTS COMPLETE ✅")
    print("=" * 60)

finally:
    print("\n[*] Stopping server...")
    proc.terminate()
    proc.wait(timeout=5)
    print("[+] Server stopped")
