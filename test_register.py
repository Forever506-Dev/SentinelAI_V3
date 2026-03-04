import asyncio
import os
import sys

_backend_dir = os.environ.get(
    "SENTINEL_BACKEND_DIR",
    os.path.join(os.path.dirname(__file__), "backend"),
)
sys.path.insert(0, _backend_dir)

async def test():
    from app.core.database import async_session_factory, engine, Base
    from app.models.user import User
    from app.core.security import hash_password

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        try:
            user = User(
                email="test@sentinelai.dev",
                username="testuser",
                hashed_password=hash_password("TestPass123!"),
                full_name="Test User",
                role="analyst",
            )
            session.add(user)
            await session.flush()
            await session.refresh(user)
            print(f"SUCCESS: User created id={user.id}, type={type(user.id)}")
            await session.commit()
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            await session.rollback()

asyncio.run(test())
