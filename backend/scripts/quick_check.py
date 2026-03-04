import os
import requests

_password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
if not _password:
    raise SystemExit(
        "Error: SENTINEL_ADMIN_PASSWORD environment variable is not set.\n"
        "Usage:  SENTINEL_ADMIN_PASSWORD='...' python quick_check.py"
    )

token = requests.post('http://localhost:8080/api/v1/auth/login', json={'username':'admin','password':_password}).json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

r = requests.get('http://localhost:8080/api/v1/agents', headers=headers)
print(f"Agents response status: {r.status_code}")
print(f"Agents response: {r.text[:500]}")

r2 = requests.get('http://localhost:8080/api/v1/agents?include_decommissioned=true', headers=headers)
print(f"\nAll agents response: {r2.text[:500]}")

r3 = requests.get('http://localhost:8080/api/v1/dashboard/stats', headers=headers)
print(f"\nDashboard stats: {r3.text[:500]}")
