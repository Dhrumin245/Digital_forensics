"""
Application configuration — loaded from environment variables.
Copy .env.example to .env and fill in values before running.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://forensics:forensics@localhost:5432/forensics"

    # ── JWT (RS256) ───────────────────────────────────────────────────────────
    # Generate with: openssl genrsa -out private.pem 2048
    #                openssl rsa -in private.pem -pubout -out public.pem
    JWT_PRIVATE_KEY: str = "test-private-key"        # Full PEM string, newlines as \n
    JWT_PUBLIC_KEY: str = "test-public-key"         # Full PEM string, newlines as \n
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int  = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int    = 7

    # ── Kafka ─────────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_CUSTODY:     str = "forensics.custody"
    KAFKA_TOPIC_AUDIT:       str = "forensics.audit"
    KAFKA_TOPIC_ALERTS:      str = "forensics.alerts"

    # OpenTelemetry collector / Jaeger OTLP gRPC endpoint.  Keep this
    # environment-configurable: Docker and Kubernetes use different service DNS
    # names.
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "localhost:4317"

    # ── Object storage (MinIO / S3) ───────────────────────────────────────────
    S3_ENDPOINT:          str = "http://localhost:9000"
    S3_ACCESS_KEY:        str = "minioadmin"
    S3_SECRET_KEY:        str = "minioadmin"
    S3_BUCKET_EVIDENCE:   str = "forensics-evidence"
    S3_BUCKET_AUDIT_MIRROR: str = "forensics-audit-mirror"

    # ── Redis (rate limiting) ─────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── CORS ─────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    # ── Verification portal signing ───────────────────────────────────────────
    SIGNING_KEY_ID: str = "forensics-verify-key-v1"

    # ── File upload limits ────────────────────────────────────────────────────
    MAX_EVIDENCE_FILE_SIZE_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB

    # ── Rate limiting (verification portal) ──────────────────────────────────
    VERIFY_RATE_LIMIT_PER_MINUTE: int = 10
    VERIFY_RATE_LIMIT_PER_HOUR:   int = 100


settings = Settings()
