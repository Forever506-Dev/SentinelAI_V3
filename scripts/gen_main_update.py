import re

path = r"F:\SentinelAI\backend\app\main.py"
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add osint import
old_import = "from app.api.routes import agents, alerts, analysis, auth, dashboard"
new_import = "from app.api.routes import agents, alerts, analysis, auth, dashboard, osint"
content = content.replace(old_import, new_import)

# Add osint router after analysis router
old_analysis_router = '''    application.include_router(
        analysis.router, prefix=f"{api_prefix}/analysis", tags=["AI Analysis"]
    )'''
new_analysis_router = '''    application.include_router(
        analysis.router, prefix=f"{api_prefix}/analysis", tags=["AI Analysis"]
    )
    application.include_router(
        osint.router, prefix=f"{api_prefix}/osint", tags=["OSINT Tools"]
    )'''
content = content.replace(old_analysis_router, new_analysis_router)

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"OK {path}")
