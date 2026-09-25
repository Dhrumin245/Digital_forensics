#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# deploy.sh — ForensicChain Phase 5 deployment script
#
# Usage:
#   ./scripts/deploy.sh local      # Minikube (dev)
#   ./scripts/deploy.sh dev        # K8s dev cluster
#   ./scripts/deploy.sh prod       # Production cluster
#
# Prerequisites:
#   - kubectl configured for target cluster
#   - kustomize installed (or kubectl >= 1.27)
#   - Docker image pushed to registry
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

ENV=${1:-local}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

log() { echo "$(date '+%H:%M:%S')  $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Validate prerequisites ────────────────────────────────────────────────────
command -v kubectl  &>/dev/null || die "kubectl not found"
command -v kustomize &>/dev/null || command -v kubectl &>/dev/null || die "kustomize not found"

log "Deploying ForensicChain to environment: $ENV"

# ── Local (Minikube) setup ────────────────────────────────────────────────────
if [[ "$ENV" == "local" ]]; then
  log "Setting up Minikube..."

  # Start Minikube if not running
  if ! minikube status &>/dev/null; then
    minikube start \
      --driver=docker \
      --cpus=4 \
      --memory=6144 \
      --kubernetes-version=v1.28.0
  fi

  # Enable required addons
  minikube addons enable ingress
  minikube addons enable metrics-server

  # Build and load image into Minikube (skip registry push)
  log "Building Docker image..."
  docker build -t forensics-api:latest "$ROOT/../forensics-api"
  minikube image load forensics-api:latest

  KUSTOMIZE_PATH="$ROOT/k8s/overlays/dev"

else
  # ── Remote cluster deployment ───────────────────────────────────────────────
  KUSTOMIZE_PATH="$ROOT/k8s/overlays/$ENV"
  [[ -d "$KUSTOMIZE_PATH" ]] || die "No overlay found for environment: $ENV"
fi

# ── Apply Argo CD first (if prod) ────────────────────────────────────────────
if [[ "$ENV" == "prod" ]]; then
  log "Installing Argo CD..."
  kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -n argocd \
    -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

  log "Waiting for Argo CD to be ready..."
  kubectl rollout status deployment/argocd-server -n argocd --timeout=120s

  log "Applying Argo CD Application manifests..."
  kubectl apply -f "$ROOT/argocd/applications.yaml"

  log "Argo CD will now manage the deployment. Check status at:"
  log "  kubectl port-forward svc/argocd-server -n argocd 8080:443"
  log "  https://localhost:8080"
  exit 0
fi

# ── Apply Kubernetes manifests ────────────────────────────────────────────────
log "Applying manifests from: $KUSTOMIZE_PATH"
kubectl apply -k "$KUSTOMIZE_PATH"

# ── Wait for core services ────────────────────────────────────────────────────
log "Waiting for PostgreSQL..."
kubectl rollout status statefulset/postgres -n forensics --timeout=120s

log "Waiting for Kafka..."
kubectl rollout status statefulset/kafka -n forensics --timeout=120s

log "Waiting for Kafka topic initialisation job..."
kubectl wait --for=condition=complete job/kafka-topic-init \
  -n forensics --timeout=60s 2>/dev/null || log "  (topic-init may already be complete)"

log "Waiting for MinIO..."
kubectl rollout status statefulset/minio -n forensics --timeout=60s

log "Waiting for API pods..."
kubectl rollout status deployment/forensics-api -n forensics --timeout=120s

log "Waiting for Prometheus..."
kubectl rollout status deployment/prometheus -n forensics --timeout=60s || true

log "Waiting for Grafana..."
kubectl rollout status deployment/grafana -n forensics --timeout=60s || true

# ── Run DB migrations ─────────────────────────────────────────────────────────
log "Running Alembic migrations..."
API_POD=$(kubectl get pod -n forensics -l app=forensics-api \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -n "$API_POD" ]]; then
  kubectl exec "$API_POD" -n forensics -- alembic upgrade head
  log "Migrations complete"
else
  log "WARNING: No API pod found — migrations skipped"
fi

# ── Print access URLs ─────────────────────────────────────────────────────────
log ""
log "══════════════════════════════════════════════════"
log "  ForensicChain deployed to: $ENV"
log "══════════════════════════════════════════════════"

if [[ "$ENV" == "local" ]]; then
  MINIKUBE_IP=$(minikube ip)
  log "  API docs:     http://$MINIKUBE_IP/api/v1/docs"
  log "  Health:       http://$MINIKUBE_IP/health"
  log ""
  log "  Port-forwards (run in separate terminals):"
  log "    kubectl port-forward svc/grafana-service     3001:3000 -n forensics"
  log "    kubectl port-forward svc/jaeger-service      16686:16686 -n forensics"
  log "    kubectl port-forward svc/prometheus-service  9090:9090 -n forensics"
  log "    kubectl port-forward svc/minio-service       9001:9001 -n forensics"
else
  log "  API:       https://forensics.yourdomain.com/api/v1/docs"
  log "  Grafana:   https://forensics.yourdomain.com/grafana"
  log "  Jaeger:    (internal) kubectl port-forward svc/jaeger-service 16686:16686 -n forensics"
fi

log ""
log "  Run resilience tests:"
log "    python scripts/resilience_tests.py"
log ""
log "  Check pod status:"
log "    kubectl get pods -n forensics"
log ""
