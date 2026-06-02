"""
observability/telemetry.py — OpenTelemetry setup for Q-BOM AI.

Instruments:
  - FastAPI HTTP requests (auto-instrumentation)
  - SQLAlchemy queries
  - Custom spans for agent nodes and retrieval calls
  - Exports to Azure Monitor / OTLP collector

LangSmith handles LangChain/LangGraph traces separately via env vars.
This module covers the infrastructure-level observability layer.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("qbom.telemetry")

# ── Graceful degradation if OTel not installed ─────────────────────────────────
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    log.warning("opentelemetry packages not installed — telemetry disabled")


def setup_telemetry(app) -> None:
    """
    Wire OpenTelemetry into the FastAPI app.
    Call once at application startup, before any requests are served.
    """
    if not OTEL_AVAILABLE:
        return

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    environment    = os.getenv("ENVIRONMENT", "development")

    resource = Resource.create({
        SERVICE_NAME:    "qbom-ai-backend",
        SERVICE_VERSION: "1.0.0",
        "deployment.environment": environment,
    })

    # ── Tracer provider ────────────────────────────────────────────────────────
    tracer_provider = TracerProvider(resource=resource)

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            tracer_provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))
            )
            log.info(f"OTel traces -> {otlp_endpoint}")
        except Exception as e:
            log.warning(f"OTLP exporter setup failed: {e}")

    if environment == "development":
        # Print spans to console in dev
        tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(tracer_provider)

    # ── Metrics provider ───────────────────────────────────────────────────────
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=otlp_endpoint),
                export_interval_millis=30_000,
            )
            metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
        except Exception as e:
            log.warning(f"OTLP metrics exporter setup failed: {e}")

    # ── Instrument libraries ───────────────────────────────────────────────────
    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls="/api/health,/docs,/openapi.json,/redoc",
    )
    SQLAlchemyInstrumentor().instrument(enable_commenter=True)
    HTTPXClientInstrumentor().instrument()

    log.info("OpenTelemetry instrumentation active")


# ── Custom span helpers used by agent nodes ────────────────────────────────────
def get_tracer():
    if not OTEL_AVAILABLE:
        return _NoopTracer()
    return trace.get_tracer("qbom.agents")


class _NoopTracer:
    """Fallback when OTel is not installed — all methods are no-ops."""
    def start_as_current_span(self, name, **kwargs):
        from contextlib import contextmanager
        @contextmanager
        def _noop():
            yield _NoopSpan()
        return _noop()


class _NoopSpan:
    def set_attribute(self, *a, **k): pass
    def record_exception(self, *a, **k): pass
    def set_status(self, *a, **k): pass


def record_scan_metrics(
    scan_id: str,
    target: str,
    finding_count: int,
    hndl_score: float,
    duration_ms: float,
) -> None:
    """Record custom metrics for a completed scan."""
    if not OTEL_AVAILABLE:
        return
    try:
        meter = metrics.get_meter("qbom.scans")
        meter.create_counter("qbom.scans.completed").add(1, {
            "target_type": "repo" if "github" in target else "website",
        })
        meter.create_histogram("qbom.scans.duration_ms").record(duration_ms)
        meter.create_histogram("qbom.scans.hndl_score").record(hndl_score)
        meter.create_histogram("qbom.scans.finding_count").record(finding_count)
    except Exception:
        pass


def record_retrieval_metrics(query: str, bm25_count: int, dense_count: int, rrf_count: int) -> None:
    """Record metrics for a hybrid retrieval call."""
    if not OTEL_AVAILABLE:
        return
    try:
        meter = metrics.get_meter("qbom.retrieval")
        meter.create_counter("qbom.retrieval.calls").add(1)
        meter.create_histogram("qbom.retrieval.bm25_results").record(bm25_count)
        meter.create_histogram("qbom.retrieval.dense_results").record(dense_count)
        meter.create_histogram("qbom.retrieval.rrf_results").record(rrf_count)
    except Exception:
        pass
