# =============================================================================
# ciem/gcp_iam.tf — TigerGate CNAPP: CIEM – GCP IAM Overpermission
# =============================================================================
# PURPOSE: GCP IAM misconfigurations giving excessive permissions to service
# accounts, user principals, and workloads. Triggers TigerGate CIEM findings
# and Google Cloud Security Command Center (SCC) recommendations.
#
# CIEM FINDINGS:
#   GCP-IAM-001: Service account with roles/owner on project level
#   GCP-IAM-002: Default service account used (not dedicated per-workload)
#   GCP-IAM-003: allUsers/allAuthenticatedUsers granted access (public!)
#   GCP-IAM-004: Service account key with no expiration
#   GCP-IAM-005: User account has primitive role (editor/owner) — not fine-grained
# =============================================================================

terraform {
  required_providers { google = { source = "hashicorp/google", version = "~> 5.0" } }
}

provider "google" {
  project = "megacorp-production-334891"
  region  = "us-central1"
}

# ── GCP-IAM-001: Service Account with Project Owner ──────────────────────────
resource "google_project_iam_member" "deployer_owner" {
  project = "megacorp-production-334891"
  # 🔴 GCP-IAM-001: roles/owner = full admin access including billing and IAM!
  role    = "roles/owner"         # Should be a specific predefined role like roles/run.admin
  member  = "serviceAccount:deployer@megacorp-production-334891.iam.gserviceaccount.com"
}

# ── GCP-IAM-002: Using Default Compute Service Account ───────────────────────
resource "google_compute_instance" "vm" {
  name         = "prod-app-server"
  machine_type = "n2-standard-4"
  zone         = "us-central1-a"

  service_account {
    # 🔴 GCP-IAM-002: Default compute SA has broad project-level permissions
    # Should create a dedicated minimal-permission SA per workload
    email  = "123456789-compute@developer.gserviceaccount.com"   # 🔴 Default SA!
    # 🔴 GCP-IAM-002: cloud-platform scope = ALL GCP API access!
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]  # Should be specific scopes
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"  # 🔴 Not pinned to specific version
    }
  }
  network_interface {
    network       = "default"     # 🔴 Using default VPC — no isolation
    access_config {}              # 🔴 Assigns public IP automatically
  }
}

# ── GCP-IAM-003: Public Access to Storage Bucket ─────────────────────────────
resource "google_storage_bucket_iam_member" "public_bucket" {
  bucket = "megacorp-prod-assets"
  role   = "roles/storage.objectViewer"
  # 🔴 GCP-IAM-003: allUsers = anyone on the internet can read!
  member = "allUsers"    # Should never be used for production data
}

resource "google_storage_bucket_iam_member" "all_auth_write" {
  bucket = "megacorp-user-uploads"
  role   = "roles/storage.objectCreator"
  # 🔴 GCP-IAM-003: allAuthenticatedUsers = any Google account can write!
  member = "allAuthenticatedUsers"
}

# ── GCP-IAM-004: Service Account Key (Long-lived credential) ─────────────────
resource "google_service_account_key" "deployer_key" {
  service_account_id = "deployer@megacorp-production-334891.iam.gserviceaccount.com"
  # 🔴 GCP-IAM-004: Service account keys are long-lived (up to 10 years!)
  # They bypass Org Policy controls and don't respect IAM conditions
  # Best practice: Use Workload Identity Federation instead
  # 🔴 No expiration, no rotation configured
}

# ── GCP-IAM-005: Primitive Role for Human User ───────────────────────────────
resource "google_project_iam_member" "dev_editor" {
  project = "megacorp-production-334891"
  # 🔴 GCP-IAM-005: roles/editor = create/modify ALL resources except IAM
  # Includes: deploying to prod, reading all secrets, accessing all databases
  role    = "roles/editor"      # Should use granular predefined roles
  member  = "user:developer@megacorp.com"
}

# 🔴 GCP-IAM-005: No IAM conditions — access granted 24/7, no time/resource restriction
# Should use: condition { title="business-hours" expression="request.time.getHours() < 18" }
