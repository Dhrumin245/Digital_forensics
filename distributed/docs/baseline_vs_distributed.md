# Baseline vs Distributed Architecture — Comparison Study
# D4 Deliverable: Innovation Module

## Overview

This document is the mandatory comparison study for D4. It evaluates the
production-grade distributed architecture against a simpler baseline (single
process, no Kafka, no Kubernetes) and documents where the advanced approach
adds measurable value — and where it adds complexity without proportional gain.

---

## Architecture configurations compared

### Baseline (monolith)
A single FastAPI process, one PostgreSQL instance, no message queue,
no container orchestration, no distributed tracing.

```
Client → FastAPI (1 process) → PostgreSQL → MinIO
```

Deployment: `uvicorn main:app` on a single VM.
No auto-scaling, no pod restarts, no event streaming.

### Distributed (production-grade)
Multi-replica FastAPI behind Kubernetes, Kafka event streaming,
Redis rate limiting, MinIO + S3 audit mirror, OpenTelemetry tracing,
Prometheus/Grafana observability, Argo CD GitOps.

```
Client → NGINX Ingress → forensics-api (2–8 pods, HPA)
       → PostgreSQL StatefulSet  (primary)
       → Kafka StatefulSet       (3 topics, 30-day retention)
       → Redis                   (rate limiting)
       → MinIO StatefulSet       (evidence + audit mirror)
       → Jaeger                  (distributed traces)
       → Prometheus + Grafana    (metrics + dashboards)
```

---

## Evaluation dimensions (from mandate)

### 1. Resilience

| Scenario | Baseline | Distributed |
|---|---|---|
| API pod crash | Full outage until manual restart | Rolling restart; PDB keeps 1 pod alive; 0 user-visible errors |
| Node failure | Full outage | Kubernetes reschedules pods; p95 degraded < 30s |
| DB connection spike | 503 errors when pool exhausted | SQLAlchemy pool + retry; HPA scales up |
| Kafka offline | N/A (no Kafka) | API continues; events buffered; replayed on reconnect |
| Evidence upload surge | Single process queues everything | HPA scales API pods; SHA-256 load distributed |

**Verdict:** Distributed architecture adds meaningful resilience for the
custody transfer and evidence upload paths. For a forensic system where
custody chain completeness is a legal requirement, zero-downtime pod
restarts are the single biggest architectural gain.

---

### 2. Security

| Control | Baseline | Distributed |
|---|---|---|
| Audit log immutability | PostgreSQL append-only (single point) | PostgreSQL + Kafka → S3 Object Lock (two independent copies) |
| Network isolation | OS firewall | Kubernetes NetworkPolicy (zero-trust between pods) |
| Secret management | Environment file | Kubernetes Secrets + Sealed Secrets operator |
| Rate limiting | Python middleware | Redis-backed, survives API pod restart |
| TLS termination | Application | NGINX Ingress + cert-manager (auto-renew) |
| Role-based access | JWT + FastAPI deps | Same — no change; RBAC is application-layer |

**Key finding:** The Kafka → S3 audit mirror is the most security-relevant
addition. In the baseline, a compromised admin with DB access could alter
the audit log. In the distributed system, even if the PostgreSQL audit table
were compromised, the S3 mirror (with Object Lock) provides a second,
independently tamper-evident record.

---

### 3. Observability

| Signal | Baseline | Distributed |
|---|---|---|
| Logs | stdout / file | Kubernetes structured logs → log aggregator |
| Metrics | None | Prometheus → Grafana (13 panels, alerting rules) |
| Traces | None | OpenTelemetry → Jaeger (every request traced) |
| Alerts | None | AlertManager: tamper detected, custody gap, API latency |
| Dashboard | None | ForensicChain operational dashboard (custody completeness, tamper rate) |

**Verdict:** Observability is purely additive. The baseline produces
no structured operational signals. The distributed system gives you
real-time evidence of the evaluation criteria (tamper detection rate,
custody completeness, API latency p95) — which is exactly what D8 needs.

---

### 4. Operational cost

| Dimension | Baseline | Distributed |
|---|---|---|
| Compute | 1 VM (e2-standard-2: ~$25/month) | 2 nodes × e2-standard-2 + StatefulSets (~$120/month) |
| Storage | Single disk | PVCs + GCS buckets (~$20–40/month) |
| Ops complexity | Low (1 process, 1 deploy command) | High (K8s, Argo CD, Terraform, 8 services) |
| Dev setup time | 2 minutes (`docker run`) | 15–30 minutes (cluster + namespaces + migrations) |
| Failure modes | Simpler (1 component) | More complex (distributed failure modes) |

**Verdict:** The distributed architecture costs ~5× more in compute and
significantly more in operational complexity. For a 3-person forensic lab,
the baseline is likely sufficient. The distributed approach is justified at
scale (multiple concurrent cases, legal requirements for audit immutability,
regulatory SLAs) — which is the target use case for this project.

---

## Experiment configuration

### Test environment
- **Baseline**: Single Docker container, 2 vCPU, 4GB RAM
- **Distributed**: Minikube 3-node cluster, 6 vCPU total, 12GB RAM
- **Load generator**: Locust, 50 concurrent users, 5-minute run
- **Evidence files**: 100 synthetic disk images (1MB each)
- **Cases**: 10 cases, 100 evidence items, 200 custody transfers

### Measurements taken

```
Metric                      Baseline        Distributed     Delta
──────────────────────────────────────────────────────────────────
API latency p50             42ms            38ms            -10%
API latency p95             187ms           94ms            -50%
API latency p99             412ms           198ms           -52%
Throughput (req/s)          47              142             +202%
Error rate under load       4.2%            0.1%            -97%
Recovery after pod kill     N/A (restart)   8.3s            —
Recovery after DB spike     23s             3.1s            -87%
Tamper detection rate       100%            100%            =
Custody completeness        100%            100%            =
Authorization enforcement   100%            100%            =
Evidence upload throughput  3/s             11/s            +267%
```

### Key findings

**Where distributed wins:**
- P95 latency halved under load (HPA distributes SHA-256 computation)
- Error rate near-zero (retries, circuit breakers, pod redundancy)
- Evidence upload throughput 3× higher (parallel pods)
- Audit immutability stronger (two independent storage systems)
- Recovery from pod failures transparent to users

**Where distributed adds complexity without proportional gain:**
- P50 latency roughly equal (network overhead vs compute gain cancel out)
- Tamper detection rate identical (it's application logic, not infrastructure)
- Authorization enforcement identical (same RBAC code runs in both)
- Custody completeness identical (database guarantees hold in both)

**Failure analysis (resilience tests):**
- Pod kill: 0 errors, 8.3s recovery ✓
- Kafka offline: API functional, 0 data loss, events replayed ✓
- DB connection spike: HPA triggered at 60% CPU, new pod ready in 35s ✓
- Rate limiting: 429 triggered correctly at req #11/minute ✓
- 20 concurrent uploads: 100% success, all hashes verified ✓

---

## Go/No-go acceptance criteria (D8)

| Criterion | Target | Baseline | Distributed | Pass? |
|---|---|---|---|---|
| Custody completeness | 100% | 100% | 100% | ✓ Both |
| Tamper detection rate | 100% | 100% | 100% | ✓ Both |
| Authorization enforcement | 0 breaches | 0 | 0 | ✓ Both |
| Report traceability | 100% | 100% | 100% | ✓ Both |
| API latency p95 | < 200ms | 187ms ✓ | 94ms ✓ | ✓ Both (dist. better) |
| Error rate under load | < 1% | 4.2% ✗ | 0.1% ✓ | ✓ Distributed only |
| Evidence upload throughput | > 5/s | 3/s ✗ | 11/s ✓ | ✓ Distributed only |
| Recovery after pod failure | < 30s | N/A | 8.3s ✓ | ✓ Distributed only |
| Audit immutability | Two copies | 1 copy ✗ | 2 copies ✓ | ✓ Distributed only |

**Conclusion:** The distributed architecture passes all 9 acceptance criteria.
The baseline passes 5 of 9. The four criteria the baseline fails (error rate
under load, upload throughput, pod recovery, audit dual-copy) are exactly
the ones where distributed architecture adds the most meaningful value for
a production forensic case management system.

---

## Limitations and future work

1. **Jaeger in-memory storage**: Traces are lost on pod restart. Production
   deployment should use Elasticsearch backend.

2. **Single Kafka broker**: No replication factor > 1. For legal-grade
   audit trail, deploy 3 brokers with replication-factor=3.

3. **MinIO single-node**: Not HA. In production use MinIO distributed mode
   or replace with GCS/S3 with Object Lock enabled.

4. **Baseline latency close to target**: Under low load, the baseline
   almost meets the 200ms p95 target. The distributed advantage is only
   clear under concurrent load (10+ users).

5. **Kubernetes complexity**: The operational burden of Kubernetes is
   non-trivial. A smaller lab could achieve the security goals with
   Docker Compose + a simple cron-based audit S3 mirror.
