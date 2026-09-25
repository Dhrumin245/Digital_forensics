# ══════════════════════════════════════════════════════════════════
# Terraform — ForensicChain Infrastructure (GCP / GKE)
# Provisions: VPC, GKE cluster, Cloud SQL, GCS buckets, IAM
#
# Usage:
#   cd terraform
#   terraform init
#   terraform plan -var-file=dev.tfvars
#   terraform apply -var-file=dev.tfvars
# ══════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }

  # Remote state — replace bucket name with your own
  backend "gcs" {
    bucket = "forensicchain-terraform-state"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "dev | staging | prod"
  type        = string
  default     = "dev"
}

variable "cluster_node_count" {
  description = "Number of nodes per zone"
  type        = number
  default     = 2
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-g1-small"
}

# ── VPC ───────────────────────────────────────────────────────────────────────
resource "google_compute_network" "forensics_vpc" {
  name                    = "forensics-vpc-${var.environment}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "forensics_subnet" {
  name          = "forensics-subnet-${var.environment}"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.forensics_vpc.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.1.0.0/16"
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.2.0.0/20"
  }
}

# ── GKE Cluster ───────────────────────────────────────────────────────────────
resource "google_container_cluster" "forensics" {
  name     = "forensics-cluster-${var.environment}"
  location = var.region

  # Remove default node pool and create managed one below
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.forensics_vpc.name
  subnetwork = google_compute_subnetwork.forensics_subnet.name

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Workload Identity — pods use GCP service accounts without keys
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Private cluster — nodes have no public IPs
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "All (restrict in production)"
    }
  }

  # Enable Workload Identity, Binary Authorization, Network Policy
  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }

  network_policy {
    enabled = true
  }

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
}

resource "google_container_node_pool" "forensics_nodes" {
  name       = "forensics-nodes"
  cluster    = google_container_cluster.forensics.name
  location   = var.region
  node_count = var.cluster_node_count

  node_config {
    machine_type = var.environment == "prod" ? "n2-standard-4" : "e2-standard-2"
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    # Workload Identity on each node
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      environment = var.environment
      component   = "forensics"
    }
  }

  autoscaling {
    min_node_count = var.environment == "prod" ? 2 : 1
    max_node_count = var.environment == "prod" ? 10 : 3
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# ── Cloud SQL (PostgreSQL 16) ─────────────────────────────────────────────────
resource "google_sql_database_instance" "forensics_db" {
  name             = "forensics-postgres-${var.environment}"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier              = var.db_tier
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_size         = 20
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      backup_retention_settings {
        retained_backups = 30
      }
    }

    ip_configuration {
      ipv4_enabled    = false    # Private IP only
      private_network = google_compute_network.forensics_vpc.id
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
  }

  deletion_protection = var.environment == "prod" ? true : false
}

resource "google_sql_database" "forensics" {
  name     = "forensics"
  instance = google_sql_database_instance.forensics_db.name
}

resource "google_sql_user" "forensics" {
  name     = "forensics"
  instance = google_sql_database_instance.forensics_db.name
  password = var.db_password   # Set in tfvars, never hardcode
}

# ── GCS Buckets ───────────────────────────────────────────────────────────────
resource "google_storage_bucket" "evidence" {
  name          = "forensics-evidence-${var.environment}-${var.project_id}"
  location      = var.region
  force_destroy = var.environment != "prod"

  # Evidence files are immutable — Object Versioning protects against accidental deletion
  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  uniform_bucket_level_access = true
}

resource "google_storage_bucket" "audit_mirror" {
  name          = "forensics-audit-${var.environment}-${var.project_id}"
  location      = var.region
  force_destroy = false   # Never force-destroy the audit mirror

  # Object Lock equivalent — retention policy prevents deletion
  retention_policy {
    retention_period = 31536000   # 1 year in seconds
    is_locked        = var.environment == "prod" ? true : false
  }

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "cluster_name" {
  value = google_container_cluster.forensics.name
}

output "cluster_endpoint" {
  value     = google_container_cluster.forensics.endpoint
  sensitive = true
}

output "db_connection_name" {
  value = google_sql_database_instance.forensics_db.connection_name
}

output "evidence_bucket" {
  value = google_storage_bucket.evidence.name
}

output "audit_bucket" {
  value = google_storage_bucket.audit_mirror.name
}
