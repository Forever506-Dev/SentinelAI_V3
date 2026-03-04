import asyncio
import os
from httpx import AsyncClient, ASGITransport
from app.main import app

_password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
if not _password:
    raise SystemExit(
        "Error: SENTINEL_ADMIN_PASSWORD environment variable is not set.\n"
        "Usage:  SENTINEL_ADMIN_PASSWORD='...' python verify_auth_local.py"
    )


async def main() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": _password},
        )
        print("login", login_resp.status_code, login_resp.text[:300])

        if login_resp.status_code != 200:
            return

        token = login_resp.json().get("access_token")
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        print("me", me_resp.status_code, me_resp.text[:300])

        change_resp = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": _password,
                "new_password": _password,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        print("change-password", change_resp.status_code, change_resp.text[:300])


if __name__ == "__main__":
    asyncio.run(main())
