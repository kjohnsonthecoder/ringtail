# Ringtail web: stateless FastAPI checker + static BYOK page. No API key is ever needed here.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RINGTAIL_ATTACK_INDEX=/app/data/attack/enterprise-attack-20.1.index.json \
    RINGTAIL_WEB_DIR=/app/web

WORKDIR /app

# Install the library first so code-only changes reuse the dependency layer.
COPY pyproject.toml README.md LICENSE ./
COPY core core
RUN pip install ".[web]"

COPY backend backend
COPY web web
COPY data/attack/enterprise-attack-20.1.index.json data/attack/

RUN useradd --system --uid 10001 ringtail
USER ringtail

# Railway sets PORT. Proxy handling is done by the app (RINGTAIL_CLIENT_IP_HEADER), not uvicorn.
CMD ["sh", "-c", "exec uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header --no-proxy-headers"]
