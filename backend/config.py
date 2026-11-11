import os

API_KEY    = os.getenv("SENTINEL_API_KEY", "sentinel-dev-key")
DB_PATH    = os.getenv("SENTINEL_DB", "sentinel.db")
CORS_ORIGIN = os.getenv("SENTINEL_ORIGIN", "http://localhost:5173")
# Allow both localhost and 127.0.0.1 Vite origins during local demo
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "SENTINEL_ORIGINS",
        f"{CORS_ORIGIN},http://127.0.0.1:5173,http://localhost:5173",
    ).split(",")
    if o.strip()
]

# Public HTTP port the API listens on. Koyeb/Render inject PORT at runtime.
API_PORT = int(os.getenv("PORT", "8000"))

# Honeypot ports. The HTTP sensor defaults to 8080; if that equals API_PORT
# the sensor is skipped at startup so the two never fight for the socket.
SSH_PORT    = int(os.getenv("SSH_PORT",    2222))
HTTP_PORT   = int(os.getenv("HTTP_PORT",   8080))
FTP_PORT    = int(os.getenv("FTP_PORT",    2121))
TELNET_PORT = int(os.getenv("TELNET_PORT", 2323))

# Threat escalation thresholds
REPEAT_ESCALATE_HITS    = 10
REPEAT_MEDIUM_MIN_HITS  = 5

# Ambient live-attack simulator. Off by default — public deploys should show
# sensor traffic only. Set SENTINEL_LIVE_ATTACKS=1 for local demos.
LIVE_ATTACKS = os.getenv("SENTINEL_LIVE_ATTACKS", "0").lower() not in ("0", "false", "off")
LIVE_ATTACK_INTERVAL = float(os.getenv("SENTINEL_LIVE_INTERVAL", "1.6"))

# Seed a 7-day demo history when the database is empty at boot. Off by default
# so a real deployment never fabricates history. Required on hosts with an
# ephemeral filesystem, where the DB is recreated on every cold start and the
# dashboard would otherwise open with no history and undefined MTTA/MTTR.
SEED_ON_EMPTY = os.getenv("SENTINEL_SEED_ON_EMPTY", "0").lower() not in ("0", "false", "off")

# Swagger UI / OpenAPI. Off in public deploys so the attack surface and schema
# are not advertised; leave on for local development.
PUBLIC_DOCS = os.getenv("SENTINEL_PUBLIC_DOCS", "1").lower() not in ("0", "false", "off")