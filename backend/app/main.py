"""
SentinelAI Backend — Main Application Entry Point

Initializes the FastAPI application with all routes, middleware,
event handlers, and WebSocket endpoints.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.database import engine, Base
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.routes import agents, alerts, analysis, auth, dashboard, osint, remediation, firewall, approvals

logger = structlog.get_logger()


async def _ensure_tables() -> None:
    """Create database tables if they don't exist (idempotent).
    
    Uses SQLAlchemy create_all which is safe to run repeatedly.
    Alembic migrations should be run externally via CLI for production.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured via create_all")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown lifecycle."""
    logger.info("SentinelAI Backend starting up", version=settings.VERSION)

    # Ensure database tables exist
    await _ensure_tables()

    logger.info(
        "Database initialized",
        database=settings.POSTGRES_DB,
    )

    # Seed default admin user if it doesn't exist
    from sqlalchemy import select
    from app.models.user import User
    from app.core.security import hash_password

    try:
        async with AsyncSession(engine) as db:
            result = await db.execute(select(User).where(User.username == "admin"))
            admin = result.scalar_one_or_none()
            if not admin:
                # Use the configured password or auto-generate a secure one
                if settings.ADMIN_DEFAULT_PASSWORD:
                    initial_password = settings.ADMIN_DEFAULT_PASSWORD
                    password_source = "ADMIN_DEFAULT_PASSWORD env var"
                else:
                    initial_password = settings.generate_admin_password()
                    password_source = "auto-generated"

                admin = User(
                    email=settings.ADMIN_DEFAULT_EMAIL,
                    username="admin",
                    hashed_password=hash_password(initial_password),
                    full_name="Administrator",
                    role="superadmin",
                    must_change_password=True,
                )
                db.add(admin)
                await db.commit()
                logger.info(
                    "Default admin user created — CHANGE THIS PASSWORD",
                    email=settings.ADMIN_DEFAULT_EMAIL,
                    password_source=password_source,
                )
                if password_source == "auto-generated":
                    # Print clearly so the operator can log in for the first time.
                    # This is the ONLY time the password is visible.
                    print(  # noqa: T201
                        f"\n{'='*60}\n"
                        f"  SENTINELAI FIRST-RUN ADMIN PASSWORD (change immediately)\n"
                        f"  Username : admin\n"
                        f"  Password : {initial_password}\n"
                        f"  Email    : {settings.ADMIN_DEFAULT_EMAIL}\n"
                        f"{'='*60}\n"
                    )
            else:
                logger.info("Admin user already exists, skipping seed")
    except Exception as e:
        logger.warning("Admin seed failed (non-fatal)", error=str(e))

    # Start background heartbeat gap monitor
    try:
        import asyncio
        from app.api.routes.dashboard import start_heartbeat_monitor
        asyncio.create_task(start_heartbeat_monitor())
        logger.info("Background heartbeat monitor started")
    except Exception as e:
        logger.warning("Heartbeat monitor failed to start (non-fatal)", error=str(e))

    yield

    # Shutdown
    logger.info("SentinelAI Backend shutting down")
    await engine.dispose()


def create_application() -> FastAPI:
    """Factory function to create and configure the FastAPI application."""
    application = FastAPI(
        title="SentinelAI",
        description="AI-Powered Endpoint Detection & Response Platform",
        version=settings.VERSION,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # --- Middleware ---
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if not settings.DEBUG:
        application.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS,
        )

    # --- API Routes ---
    api_prefix = "/api/v1"
    application.include_router(auth.router, prefix=f"{api_prefix}/auth", tags=["Authentication"])
    application.include_router(agents.router, prefix=f"{api_prefix}/agents", tags=["Agents"])
    application.include_router(alerts.router, prefix=f"{api_prefix}/alerts", tags=["Alerts"])
    application.include_router(
        dashboard.router, prefix=f"{api_prefix}/dashboard", tags=["Dashboard"]
    )
    application.include_router(
        analysis.router, prefix=f"{api_prefix}/analysis", tags=["AI Analysis"]
    )
    application.include_router(
        osint.router, prefix=f"{api_prefix}/osint", tags=["OSINT Tools"]
    )
    application.include_router(
        remediation.router, prefix=f"{api_prefix}/remediation", tags=["Remediation"]
    )
    application.include_router(
        firewall.router, prefix=f"{api_prefix}/firewall", tags=["Firewall"]
    )
    application.include_router(
        approvals.router, prefix=f"{api_prefix}/approvals", tags=["Approvals"]
    )

    # --- Health Check ---
    @application.get("/health", tags=["System"])
    async def health_check() -> dict:
        return {
            "status": "healthy",
            "version": settings.VERSION,
            "service": "sentinelai-backend",
        }

    return application


app = create_application()
