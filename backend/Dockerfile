FROM python:3.12-slim

# iptables lets the container enforce containment when run with NET_ADMIN.
# Without it, blocks are recorded but reported as unenforced.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV SENTINEL_DB=/data/sentinel.db \
    SENTINEL_SEED_ON_EMPTY=1 \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data

EXPOSE 8000 2222 8080 2121 2323

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8000}/api/health || exit 1

# Single worker is required: SSE subscribers are held in process memory.
# $PORT is honoured because some hosts (Koyeb, Render) assign it at runtime.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
