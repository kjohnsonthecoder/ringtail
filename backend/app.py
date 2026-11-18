"""Ringtail web backend: a stateless checker. It never calls Claude and never accepts a key.

ADR 0003. The browser holds the user's key and calls Claude directly. This server only:

- POST /api/prompt  sanitizes input and builds the prompt the browser sends to Claude;
- POST /api/check   runs the same deterministic checks as `ringtail run` and CI;
- GET  /api/health  reports versions for the page and for Railway's health check;
- serves the static page in web/ (same origin, so no CORS headers are ever sent).

Run locally:  uvicorn backend.app:app --reload
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from ringtail import service

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = Path(os.environ.get("RINGTAIL_WEB_DIR", REPO_ROOT / "web"))

# Request bodies: a threat report is capped at 60k characters by sanitize; a draft relayed
# from the browser is a rule plus a handful of samples. 256 KiB covers both with room.
MAX_BODY_BYTES = int(os.environ.get("RINGTAIL_MAX_BODY_BYTES", 256 * 1024))
RATE_PER_MINUTE = int(os.environ.get("RINGTAIL_RATE_PER_MINUTE", 30))

# Headers that would carry a key. This server has no use for one, so a request carrying
# one is a client bug (or a confused user) and is refused before anything reads the body.
KEY_HEADERS = ("authorization", "x-api-key", "anthropic-api-key", "proxy-authorization")

CSP = "; ".join([
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' https://api.anthropic.com",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
])
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


class RateLimiter:
    """Sliding one-minute window per client IP, in memory. Good enough for one small
    instance; it resets on restart and isn't shared across replicas (see threat model)."""

    MAX_TRACKED = 10_000

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, seconds until the next slot frees up)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) > self.MAX_TRACKED:
                self._hits = {k: q for k, q in self._hits.items() if q and now - q[-1] < 60}
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False, max(1, int(60 - (now - q[0])) + 1)
            q.append(now)
            return True, 0


def _error(status: int, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def create_app(rate_per_minute: int = RATE_PER_MINUTE, max_body: int = MAX_BODY_BYTES,
               web_dir: Path | None = WEB_DIR) -> FastAPI:
    # No interactive docs: Swagger UI loads scripts from a CDN, which the CSP forbids.
    app = FastAPI(title="Ringtail", docs_url=None, redoc_url=None)
    limiter = RateLimiter(rate_per_minute)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if any(h in request.headers for h in KEY_HEADERS):
            resp = _error(400, "This server never accepts API keys. Your key goes only from your "
                               "browser to api.anthropic.com. Remove the header and try again.")
        elif request.url.path.startswith("/api/") and request.method == "POST":
            resp = None
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                resp = _error(411, "Content-Length is required")
            elif int(length) > max_body:
                resp = _error(413, f"request body is over {max_body} bytes")
            else:
                ip = request.client.host if request.client else "unknown"
                ok, retry = limiter.allow(ip)
                if not ok:
                    resp = _error(429, "too many requests; slow down",
                                  {"Retry-After": str(retry)})
            if resp is None:
                resp = await call_next(request)
        else:
            resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    async def _json_body(request: Request):
        raw = await request.body()
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise service.ServiceError("request body must be valid JSON") from None

    @app.exception_handler(service.ServiceError)
    async def _service_error(_request: Request, exc: service.ServiceError):
        return _error(400, str(exc))

    @app.exception_handler(Exception)
    async def _unexpected(_request: Request, _exc: Exception):
        # Never echo internals or request content back.
        return _error(500, "internal error")

    @app.get("/api/health")
    def health():
        return service.info()

    @app.post("/api/prompt")
    async def prompt(request: Request):
        body = await _json_body(request)
        return await run_in_threadpool(service.build_prompt, body)

    @app.post("/api/check")
    async def check(request: Request):
        body = await _json_body(request)
        # pySigma and the matcher are CPU-bound; keep them off the event loop.
        return await run_in_threadpool(service.check, body)

    if web_dir is not None and (Path(web_dir) / "index.html").is_file():
        app.mount("/", StaticFiles(directory=web_dir, html=True), name="web")

    return app


app = create_app()
