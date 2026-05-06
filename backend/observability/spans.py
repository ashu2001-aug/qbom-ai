"""
observability/spans.py — Span decorators for agent nodes and service functions.

Usage:
    from observability.spans import traced

    @traced("scanner.scan_directory")
    def my_function(...):
        ...
"""
from __future__ import annotations

import functools
import time
from typing import Callable, Any

from observability.telemetry import get_tracer


def traced(span_name: str, **static_attrs):
    """
    Decorator that wraps a sync or async function in an OTel span.
    Automatically records exceptions and sets error status.

    Example:
        @traced("enricher.hndl_score", component="enricher")
        async def calculate(...):
            ...
    """
    def decorator(fn: Callable) -> Callable:
        import asyncio

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                for k, v in static_attrs.items():
                    span.set_attribute(k, str(v))
                t0 = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                    span.set_attribute("duration_ms", round((time.monotonic() - t0) * 1000, 1))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    try:
                        from opentelemetry.trace import StatusCode
                        span.set_status(StatusCode.ERROR, str(e))
                    except Exception:
                        pass
                    raise

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                for k, v in static_attrs.items():
                    span.set_attribute(k, str(v))
                t0 = time.monotonic()
                try:
                    result = fn(*args, **kwargs)
                    span.set_attribute("duration_ms", round((time.monotonic() - t0) * 1000, 1))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    raise

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator
