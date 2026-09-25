# ForensicChain — Phase 5: Distributed Architecture

Production-grade Kubernetes deployment with Kafka event streaming,
Prometheus/Grafana observability, Argo CD GitOps, and Terraform infrastructure.

---

## What Phase 5 adds

| Component | Purpose | D4/D8 criterion |
|---|---|---|
| Kubernetes (K8s) | Pod auto-restart, HPA scaling, zero-downtime deploys | Resilience |
| Kafka topics (3) | Custody events, audit mirror, tamper alerts | Audit immutability |
| Audit mirror consumer | Streams every audit event to S3 independently of PostgreSQL | Security — two independent copies |
| Prometheus + Grafana | 13-panel dashboard, API latency, tamper rate, custody completeness | Observability |
| Alertmanager | Immediate alert on tamper detection, email + Slack | Operational |
| Argo CD | GitOps — Git is source of truth for all deployments | Engineering |
| Terraform | GKE cluster, Cloud SQL, GCS buckets provisioned as code | Reproducibility |
| NetworkPolicy | Zero-trust between pods (API can only reach DB, Kafka, Redis, MinIO) | Security |
| HPA | Scale API pods 2→8 based on CPU/memory | Resilience |
| PodDisruptionBudget | Guarantee ≥1 pod alive during node drain | Resilience |
| Resilience test suite | 5 automated failure scenarios with measured recovery time | D4 comparison study |
| Baseline vs distributed study | Quantified comparison of both architectures | D4 deliverable |

---

## Directory structure

```
forensics-phase5/
├── k8s/
│   ├── base/
│   │   ├── namespace-config.yaml     ← Namespace, ConfigMap, Secret
│   │   ├── api-deployment.yaml       ← Deployment, Service, HPA, PDB
│   │   ├── postgres.yaml             ← StatefulSet, PVC, init ConfigMap
│   │   ├── kafka-redis-minio.yaml    ← Kafka, Redis, MinIO + init Jobs
│   │   ├── ingress-network.yaml      ← Ingress, NetworkPolicy, Jaeger
│   │   ├── observability.yaml        ← Prometheus, Grafana, Alertmanager
│   │   └── kustomization.yaml
│   └── overlays/
│       ├── dev/kustomization.yaml    ← 1 replica, relaxed limits
│       └── prod/kustomization.yaml   ← 3 replicas, strict limits, pinned image
├── terraform/
│   ├── main.tf                       ← GKE cluster, Cloud SQL, GCS buckets
│   └── dev.tfvars
├── argocd/
│   └── applications.yaml             ← ArgoCD Application + AppProject
├── observability/
│   ├── prometheus/prometheus.yaml    ← Full scrape config
│   ├── alerting/rules.yaml           ← Domain + infra alert rules
│   └── grafana/
│       ├── dashboards/
│       │   ├── forensicchain-ops.json ← 13-panel Grafana dashboard
│       │   └── dashboards.yaml        ← Dashboard provisioner
│       └── datasources/datasources.yaml
├── kafka/
│   ├── audit_mirror_consumer.py      ← S3 audit mirror Kafka consumer
│   └── consumer-deployment.yaml      ← K8s deployment for the consumer
├── scripts/
│   ├── deploy.sh                     ← One-command deploy (local/dev/prod)
│   └── resilience_tests.py           ← 5 failure scenario tests
└── docs/
    └── baseline_vs_distributed.md    ← D4 comparison study with measurements
```

---

## Quickstart — local (Minikube)

### Prerequisites
```bash
# macOS
brew install minikube kubectl kustomize terraform

# Verify
kubectl version --client
minikube version
kustomize version
```

### 1. Start Minikube and deploy everything
```bash
cd forensics-phase5
chmod +x scripts/deploy.sh
./scripts/deploy.sh local
```

This single command:
- Starts Minikube with 4 CPUs and 6GB RAM
- Builds the Docker image and loads it into Minikube
- Creates the `forensics` namespace
- Deploys all services (PostgreSQL, Kafka, Redis, MinIO, API, Prometheus, Grafana, Jaeger)
- Runs Alembic migrations
- Waits for all services to be healthy
- Prints port-forward commands

### 2. Open the dashboards (in separate terminals)
```bash
# Grafana — http://localhost:3001  (admin / ForensicAdmin123!)
kubectl port-forward svc/grafana-service 3001:3000 -n forensics

# Jaeger traces — http://localhost:16686
kubectl port-forward svc/jaeger-service 16686:16686 -n forensics

# Prometheus — http://localhost:9090
kubectl port-forward svc/prometheus-service 9090:9090 -n forensics

# API docs — http://localhost:8080/api/v1/docs
kubectl port-forward svc/forensics-api-service 8080:80 -n forensics
```

### 3. Run resilience tests
```bash
pip install httpx --break-system-packages
python scripts/resilience_tests.py
# Results written to resilience_report.json
```

---

## Quickstart — production (GKE)

### 1. Provision infrastructure with Terraform
```bash
cd terraform
terraform init
terraform plan -var-file=dev.tfvars
terraform apply -var-file=dev.tfvars

# Get cluster credentials
gcloud container clusters get-credentials \
  $(terraform output -raw cluster_name) \
  --region us-central1
```

### 2. Set up Argo CD
```bash
./scripts/deploy.sh prod
# Argo CD watches the Git repo and auto-syncs on every push to main
```

### 3. Deploy via GitOps
```bash
# Any push to main triggers Argo CD to apply k8s/overlays/prod/
git add .
git commit -m "feat: update API to v1.1.0"
git push origin main
# Argo CD detects the change and rolls out the new deployment
```

---

## Key architectural decisions

### Why Kafka instead of direct DB writes for audit events?

The audit log is written to PostgreSQL immediately on every API call (synchronous).
Kafka is an *additional* async mirror — not a replacement.

This means:
- API response time is never blocked by Kafka (fire-and-forget)
- If Kafka is down, the API continues and the DB audit log is still intact
- When Kafka comes back, the consumer replays from its last committed offset
- The S3 mirror provides a second, independent tamper-evident record

### Why HPA scales on 60% CPU (not 80%)?

Evidence uploads involve SHA-256 computation on large files. CPU spikes are
sharp and short. At 80%, by the time the new pod is scheduled and warm,
the spike is already over. At 60%, there's enough headroom to absorb the next
upload while the new pod starts.

### Why PodDisruptionBudget with minAvailable=1 instead of maxUnavailable=1?

With 2 replicas (dev minimum), `maxUnavailable=1` allows zero available pods
during a disruption. `minAvailable=1` guarantees at least one is always up,
regardless of how many replicas are running.

### Why NetworkPolicy restricts the API to specific backend ports?

Defence in depth. If the API pod were compromised, NetworkPolicy prevents
lateral movement to arbitrary services. The API can only reach:
- PostgreSQL on 5432
- Kafka on 9092
- Redis on 6379
- MinIO on 9000
- Jaeger on 4317 (telemetry)
- DNS on 53 (name resolution)

---

## Grafana dashboard panels

| Panel | Metric | D8 criterion |
|---|---|---|
| API request rate | `rate(http_requests_total[1m])` | Performance |
| Latency p50/p95/p99 | `histogram_quantile(0.95, ...)` | p95 < 200ms |
| Error rate % | `rate(5xx) / rate(total)` | < 1% |
| Active pods | `count(up == 1)` | Resilience |
| Tamper detections | `increase(status=423[24h])` | Tamper detection |
| Unauthorized attempts | `rate(status=403[5m])` | Authorization |
| Verify portal queries | `rate(/verify, 200 vs 429)` | US-13 |
| Kafka consumer lag | `kafka_consumergroup_lag` | Audit completeness |
| PostgreSQL connections | `pg_stat_activity_count` | Infrastructure |
| PostgreSQL tx rate | `rate(xact_commit[1m])` | Infrastructure |
| API memory usage | `container_memory_working_set_bytes` | Infrastructure |
| API CPU usage | `rate(cpu_usage_seconds[1m])` | Infrastructure |
| Evidence uploads/min | `rate(POST /evidence, 201[1m])` | Performance |

---

## Baseline vs distributed — headline numbers

| Metric | Baseline | Distributed | Change |
|---|---|---|---|
| API latency p95 | 187ms | 94ms | -50% |
| Error rate under load | 4.2% | 0.1% | -97% |
| Upload throughput | 3/s | 11/s | +267% |
| Recovery after pod kill | Manual | 8.3s automatic | — |
| Audit immutability | 1 copy (DB) | 2 copies (DB + S3) | +100% |
| Tamper detection | 100% | 100% | = |
| Custody completeness | 100% | 100% | = |

Full study: `docs/baseline_vs_distributed.md`

---

## Troubleshooting

```bash
# Check all pods
kubectl get pods -n forensics

# API logs
kubectl logs -l app=forensics-api -n forensics --tail=50

# Kafka consumer logs
kubectl logs -l app=audit-mirror-consumer -n forensics --tail=50

# Re-run DB migrations
API_POD=$(kubectl get pod -n forensics -l app=forensics-api -o jsonpath='{.items[0].metadata.name}')
kubectl exec $API_POD -n forensics -- alembic upgrade head

# Force a pod restart
kubectl rollout restart deployment/forensics-api -n forensics

# Check HPA status
kubectl get hpa -n forensics

# Describe a failing pod
kubectl describe pod <pod-name> -n forensics

# Check PVC binding
kubectl get pvc -n forensics
```
