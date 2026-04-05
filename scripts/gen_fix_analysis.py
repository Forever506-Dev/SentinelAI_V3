path = r"F:\SentinelAI\backend\app\api\routes\analysis.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix the imports
content = content.replace(
    "from app.core.database import get_session",
    "from app.core.database import get_db"
)
content = content.replace(
    "from app.models.telemetry import TelemetryEvent",
    "from app.models.event import TelemetryEvent"
)
content = content.replace(
    "db: AsyncSession = Depends(get_session)",
    "db: AsyncSession = Depends(get_db)"
)

with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write(content)
print(f"OK {path}")
