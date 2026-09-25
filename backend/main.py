"""
Cryptographically Verifiable Digital Forensics API
FastAPI application entry point
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from core.config import settings
from core.database import create_tables
from core.events import shutdown_producer
from routers.cases import router as cases_router
from routers.evidence import router as evidence_router
from routers.remaining_routers import (
    router_auth, router_custody, router_tasks,
    router_findings, router_reports, router_verify,
    router_users, router_audit,
)

# ── OpenTelemetry setup ───────────────────────────────────────────────────────
def _setup_tracing() -> None:
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint="http://jaeger:4317"))
    )
    trace.set_tracer_provider(provider)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    _setup_tracing()
    await create_tables()          # Dev only — use Alembic in production
    yield
    # Shutdown
    await shutdown_producer()      # Flush Kafka producer


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Cryptographically Verifiable Digital Forensics API",
    version="1.0.0",
    description=(
        "Case intake, evidence registry, chain of custody, "
        "report versioning, and public verification."
    ),
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
P = "/api/v1"

app.include_router(router_auth,     prefix=f"{P}/auth",    tags=["Auth"])
app.include_router(cases_router,    prefix=f"{P}/cases",   tags=["Cases"])
app.include_router(evidence_router, prefix=f"{P}/cases",   tags=["Evidence"])
app.include_router(router_custody,  prefix=f"{P}/cases",   tags=["Custody"])
app.include_router(router_tasks,    prefix=f"{P}/cases",   tags=["Tasks"])
app.include_router(router_findings, prefix=f"{P}/cases",   tags=["Findings"])
app.include_router(router_reports,  prefix=f"{P}/cases",   tags=["Reports"])
app.include_router(router_verify,   prefix=f"{P}/verify",  tags=["Verify"])
app.include_router(router_users,    prefix=f"{P}/users",   tags=["Users"])
app.include_router(router_audit,    prefix=f"{P}/audit",   tags=["Audit"])

# ── Prometheus metrics ────────────────────────────────────────────────────────
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── OpenTelemetry FastAPI instrumentation ─────────────────────────────────────
FastAPIInstrumentor.instrument_app(app)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": "1.0.0"}
