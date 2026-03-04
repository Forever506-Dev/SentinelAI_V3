import os
import requests, json

_password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
if not _password:
    raise SystemExit(
        "Error: SENTINEL_ADMIN_PASSWORD environment variable is not set.\n"
        "Usage:  SENTINEL_ADMIN_PASSWORD='...' python test_agents.py"
    )

r = requests.post('http://localhost:8080/api/v1/auth/login', json={'username':'admin','password':_password})
token = r.json()['access_token']

# List agents
agents = requests.get('http://localhost:8080/api/v1/agents', headers={'Authorization': f'Bearer {token}'})
data = agents.json()
print(f"Total agents: {data.get('total', 0)}")
for a in data.get('agents', []):
    aid = a['id'][:8]
    st = a['status']
    hn = a['hostname']
    cpu = a.get('cpu_usage')
    mem = a.get('memory_usage')
    hb = a.get('last_heartbeat', '?')
    print(f"  {aid}  status={st:15s} host={hn:20s} cpu={cpu} mem={mem} hb={hb}")

# Try decommission of the first agent
if data.get('agents'):
    first = data['agents'][0]
    print(f"\nTrying to decommission agent {first['id'][:8]} ({first['hostname']})...")
    dr = requests.delete(f"http://localhost:8080/api/v1/agents/{first['id']}", headers={'Authorization': f'Bearer {token}'})
    print(f"  Response: {dr.status_code} {dr.text}")
    
    # Check again
    agents2 = requests.get('http://localhost:8080/api/v1/agents', headers={'Authorization': f'Bearer {token}'})
    data2 = agents2.json()
    print(f"\nAfter decommission - Total agents: {data2.get('total', 0)}")
    for a in data2.get('agents', []):
        print(f"  {a['id'][:8]}  status={a['status']}")
