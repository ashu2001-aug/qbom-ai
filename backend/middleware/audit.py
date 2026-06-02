"""
middleware/audit.py — Audit logging middleware.

Records every authenticated API call to the audit_log table.
Used for: billing attribution, security investigation, API key usage analytics.
"""
from __future__ import annotations

import hashlib
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Paths to skip — health checks and asset routes
SKIP_PATHS = frozenset(["/api/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"])


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        if path in SKIP_PATHS or request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        start      = time.monotonic()
        response   = await call_next(request)
        duration   = round((time.monotonic() - start) * 1000, 1)

        # Extract API key from request state (set by AuthMiddleware)
        api_key    = getattr(request.state, "api_key", None)
        tier       = getattr(request.state, "tier", None)
        scan_id    = request.path_params.get("scan_id")

        if api_key:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")

            # Fire-and-forget DB write — don't block the response
            import asyncio
            asyncio.create_task(_write_audit_log(
                api_key_hash=key_hash,
                tier=tier,
                method=request.method,
                path=path,
                status_code=response.status_code,
                duration_ms=duration,
                ip_address=ip.split(",")[0].strip(),
                scan_id=scan_id,
            ))

        return response


async def _write_audit_log(**kwargs) -> None:
    """Write a single audit log row. Swallows errors silently."""
    try:
        from models.db import AsyncSessionLocal, AuditLog

        async with AsyncSessionLocal() as db:
            db.add(AuditLog(**kwargs))
            await db.commit()
    except Exception:
        pass  # Audit failures must never break the main request path
