# Cryptographically Verifiable Digital Forensics API

A production-grade FastAPI backend for managing forensic cases, evidence, chain
of custody, examiner tasks, findings, and versioned reports — with cryptographic
tamper detection and a public verification portal.

---

## Project structure

```
forensics-api/
├── main.py                      # FastAPI app entry point, router registration
├── schemas.py                   # All Pydantic request/response models
├── models.py                    # SQLAlchemy ORM models (all 7 modules)
├── requirements.txt             # Pinned Python dependencies
├── Dockerfile                   # Multi-stage Docker build
├── docker-compose.yml           # Full local dev stack (API + DB + Kafka + MinIO + Redis + Observability)
│
├── core/
│   ├── config.py                # Pydantic Settings — all env vars
│   └── security.py             # JWT auth, RBAC, SHA-256 helpers
│
├── routers/
│   ├── cases.py                 # US-01, US-02, US-03
│   ├── evidence.py              # US-04, US-05, US-06
│   └── all_routers.py           # custody, tasks, findings, reports, verify, users, audit
│
├── db/
│   └── init.sql                 # Schema, triggers, roles, sequences
│
├── observability/
│   ├── prometheus.yml           # Prometheus scrape config
│   └── grafana/                 # Dashboard JSON + datasource config (add manually)
│
├── tests/
│   └── test_core.py             # 35+ unit tests covering crypto, RBAC, state transitions
│
├── openapi.yaml                 # Full OpenAPI 3.1 spec (all 16 user stories)
└── .github/
    └── workflows/
        └── ci.yml               # GitHub Actions — lint, test, security scan, Docker build
```

---

## Modules and user stories

| Module | User stories | Endpoint prefix |
|---|---|---|
| Auth | Login, token refresh | `/api/v1/auth` |
| Cases | US-01 Create, US-02 Assign, US-03 Status transitions | `/api/v1/cases` |
| Evidence | US-04 Upload + hash, US-05 Import from Autopsy/FTK, US-06 Integrity check | `/api/v1/cases/{id}/evidence` |
| Custody | US-07 Transfer, US-08 Chain of custody view | `/api/v1/cases/{id}/evidence/{id}/custody` |
| Tasks | US-09 Assign examiner tasks | `/api/v1/cases/{id}/tasks` |
| Findings | US-10 Record findings with attachments | `/api/v1/cases/{id}/tasks/{id}/findings` |
| Reports | US-11 Versioned reports, US-12 Court lock, US-14 PDF | `/api/v1/cases/{id}/reports` |
| Verify | US-13 Public hash verification (no auth) | `/api/v1/verify/{hash}` |
| Users | US-16 User management | `/api/v1/users` |
| Audit | US-15 Immutable audit log | `/api/v1/audit` |

---

## Quickstart

### Prerequisites
- Docker and Docker Compose
- Python 3.12+ (for local dev without Docker)
- OpenSSL (for JWT key generation)

### 1. Generate JWT keys

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### 2. Create your .env file

```bash
cp .env.example .env
# Then paste your private.pem and public.pem contents into .env as single-line strings
# Replace newlines with \n
```

`.env.example`:
```
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
DATABASE_URL=postgresql+asyncpg://forensics:forensics@db:5432/forensics
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
S3_ENDPOINT=http://minio:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
REDIS_URL=redis://redis:6379/0
```

### 3. Start all services

```bash
docker compose up -d
```

This starts:
- **API** at http://localhost:8000
- **Swagger UI** at http://localhost:8000/api/v1/docs
- **PostgreSQL** at localhost:5432
- **Kafka** at localhost:9092
- **MinIO console** at http://localhost:9001 (minioadmin / minioadmin)
- **Prometheus** at http://localhost:9090
- **Grafana** at http://localhost:3001 (admin / admin)
- **Jaeger UI** at http://localhost:16686

### 4. Run database migrations

```bash
# With Docker
docker compose exec api alembic upgrade head

# Locally
alembic upgrade head
```

### 5. Run the test suite

```bash
# Unit tests only (no DB needed)
pytest tests/ -v

# With coverage
pytest tests/ --cov=. --cov-report=term-missing

# Integration tests (requires running DB)
pytest tests/ -m integration -v
```

### 6. Load test

```bash
# Install locust
pip install locust

# Run load test against the verification portal (public endpoint)
locust -f tests/locustfile.py --host=http://localhost:8000
```

---

## Key architectural decisions

### Cryptographic immutability
- SHA-256 computed **server-side** on every upload — client hashes are never trusted
- Hash re-verified on **every access and download** — not just at intake
- Custody records are immutable once accepted — DB trigger prevents UPDATE
- Report versions are append-only — DB trigger prevents DELETE
- Audit log in separate schema — app DB user has INSERT + SELECT only, no UPDATE/DELETE

### Distributed architecture (Phase 5)
- **Kafka** publishes events for every custody transfer and tamper alert
  — decouples audit trail from the API request lifecycle
- **Kafka consumer** mirrors every audit event to S3 (Object Lock) in real time
  — even a compromised DB cannot erase the audit trail
- **OpenTelemetry** instruments every API request — traces visible in Jaeger
- **Prometheus + Grafana** expose API latency, error rate, evidence upload count

### Role-based access control
All roles are enforced at two levels:
1. **Route level** — `require_roles()` dependency rejects wrong roles with HTTP 403
2. **Case level** — even a correctly-roled user cannot access a case they are not assigned to

Roles: `CaseManager | LabTechnician | Examiner | LegalReviewer | Admin | PublicVerifier`

### Public verification portal (US-13)
- No authentication required — designed for lawyers and judges
- Rate limited: 10 req/min per IP, 100 req/hour per IP (Redis)
- Sealed cases and unknown hashes return identical `not_found` responses
  — prevents enumeration attacks (MC-07)
- Response signed with RSA private key — verifier can confirm authenticity

---

## Evaluation metrics (D8)

| Metric | Target | How to measure |
|---|---|---|
| Custody completeness | 100% | Run `GET /cases/{id}/evidence/{id}/custody` — check `chain_complete` |
| Tamper detection rate | 100% | Inject 10 modified files, verify all flagged |
| Authorization enforcement | 0 breaches | Run 20 unauthorized API calls, all must return 403 |
| Report traceability | 100% | Every report version has author, timestamp, hash |
| API latency (p95) | < 200ms | Prometheus histogram — `http_request_duration_seconds` |
| Usability | > 80% task completion | Ask 3 users to register evidence and verify a hash |

---

## Adding a migration (Alembic)

```bash
# Auto-generate from model changes
alembic revision --autogenerate -m "add column X to evidence"

# Apply
alembic upgrade head

# Roll back one
alembic downgrade -1
```

---

## Observability endpoints

| Endpoint | What it shows |
|---|---|
| `GET /health` | API liveness |
| `GET /metrics` | Prometheus metrics |
| Jaeger UI :16686 | Request traces |
| Grafana :3001 | Dashboards |
| Kafka topics | `forensics.custody`, `forensics.audit`, `forensics.alerts` |

---

## Security notes

- Never commit `.env`, `private.pem`, or `public.pem` to Git
- The `forensics_app` DB role has no DELETE on evidence, report_versions, or audit_log
- DB triggers enforce immutability at the Postgres level — independent of app logic
- All timestamps are set server-side — client-supplied timestamps are ignored
- The verification portal uses constant-time responses for not_found to prevent timing attacks
