"""Quick script to reset the admin user's password to the configured default."""
import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import engine
from app.core.security import hash_password
from app.core.config import settings


async def reset_admin():
    if not settings.ADMIN_DEFAULT_PASSWORD:
        print("Error: ADMIN_DEFAULT_PASSWORD environment variable is not set.")
        print("Set it before running this script:  export ADMIN_DEFAULT_PASSWORD='...'")
        return

    async with AsyncSession(engine) as db:
        result = await db.execute(
            text("SELECT id, username, email FROM users WHERE username = 'admin'")
        )
        row = result.first()
        if row:
            new_hash = hash_password(settings.ADMIN_DEFAULT_PASSWORD)
            await db.execute(
                text(
                    "UPDATE users SET hashed_password = :pw, role = 'admin',"
                    " must_change_password = true WHERE username = 'admin'"
                ),
                {"pw": new_hash},
            )
            await db.commit()
            print(f"Admin password reset successfully (email: {row.email}).")
            print("The user will be required to change their password on next login.")
        else:
            print("No admin user found - will be created on startup")
    await engine.dispose()


asyncio.run(reset_admin())
