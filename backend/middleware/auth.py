"""
middleware/auth.py — API key authentication + rate limiting middleware.
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ── Simple in-memory rate limiter (use Redis in production) ───────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 60          # requests
RATE_WINDOW = 60         # seconds

# ── Demo API keys (use a database in production) ───────────────────────────────
VALID_KEYS = {
    "qbom-demo-key-2025": {"tier": "free", "rate_limit": 20},
    "qbom-pro-key-2025":  {"tier": "pro",  "rate_limit": 200},
}

OPEN_PATHS = {"/api/health", "/docs", "/openapi.json", "/redoc"}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Skip auth for open paths and WebSocket upgrades
        if path in OPEN_PATHS or request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        # Extract API key
        api_key = (
            request.headers.get("X-API-Key") or
            request.headers.get("Authorization", "").removeprefix("Bearer ")
        )

        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key. Pass X-API-Key header."}
            )

        key_info = VALID_KEYS.get(api_key)
        if not key_info:
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key"}
            )

        # Rate limiting
        client_id = hashlib.md5(api_key.encode()).hexdigest()
        now = time.time()
        window_start = now - RATE_WINDOW
        _rate_store[client_id] = [t for t in _rate_store[client_id] if t > window_start]

        limit = key_info["rate_limit"]
        if len(_rate_store[client_id]) >= limit:
            retry_after = int(RATE_WINDOW - (now - _rate_store[client_id][0]))
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded. Retry after {retry_after}s."},
                headers={"Retry-After": str(retry_after)}
            )

        _rate_store[client_id].append(now)
        request.state.tier = key_info["tier"]
        request.state.api_key = api_key

        response = await call_next(request)
        response.headers["X-Rate-Limit-Remaining"] = str(limit - len(_rate_store[client_id]))
        response.headers["X-Rate-Limit-Reset"] = str(int(now + RATE_WINDOW))
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Lightweight request logger for observability."""
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 1)
        print(f"[{request.method}] {request.url.path} -> {response.status_code} ({duration_ms}ms)")
        response.headers["X-Response-Time"] = f"{duration_ms}ms"
        return response
