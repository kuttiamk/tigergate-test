# =============================================================================
# cspm/gcp_insecure.tf – TigerGate CNAPP Test: Comprehensive GCP CSPM Misconfigs
# =============================================================================
# CSPM RULES TRIGGERED (CIS GCP Benchmark):
#   CIS 5.1 – GCS bucket is publicly accessible (allUsers)
#   CIS 3.6 – SSH access from 0.0.0.0/0 in firewall rules
#   CIS 3.7 – RDP access from 0.0.0.0/0
#   CIS 3.9 – Default network with open firewall rules
#   CIS 1.5 – SA has admin role
#   CIS 1.6 – SA key never rotated
# =============================================================================

provider "google" {
  credentials = file("gcp-service-account-key.json")  # 🔴 Key file in the repo!
  project     = "tigergate-prod-99999"
  region      = "us-central1"
}

# =============================================================================
# 🔴 GCS BUCKET – Public allUsers Read + Write (CIS 5.1)
# =============================================================================
resource "google_storage_bucket" "public_data" {
  name                        = "tigergate-public-bucket"
  location                    = "US"
  uniform_bucket_level_access = false   # 🔴 Per-object ACLs allowed (legacy, bad)
  versioning { enabled = false }        # BAD: No versioning
  # No logging, no retention policy
}

# 🔴 CRITICAL: allUsers can read AND write to this bucket
resource "google_storage_bucket_iam_binding" "public_rw" {
  bucket = google_storage_bucket.public_data.name
  role   = "roles/storage.objectAdmin"           # 🔴 Write + Delete for anyone!
  members = [
    "allUsers",                                  # 🔴 Entire internet!
    "allAuthenticatedUsers",                     # BAD: All Google accounts
  ]
}

# =============================================================================
# 🔴 FIREWALL – All ports open (CIS 3.6, 3.7, 3.9)
# =============================================================================
resource "google_compute_firewall" "allow_all" {
  name    = "tigergate-allow-all"
  network = "default"                            # BAD: Using default network

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]                       # 🔴 All TCP from internet!
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]                       # 🔴 All UDP from internet!
  }
  allow { protocol = "icmp" }                   # BAD: Allows ping/network discovery

  source_ranges = ["0.0.0.0/0"]                 # 🔴 From entire internet!
}

# 🔴 BAD: Explicit SSH rule from anywhere (CIS 3.6)
resource "google_compute_firewall" "ssh_all" {
  name    = "allow-ssh-all"
  network = "default"
  allow { protocol = "tcp"; ports = ["22"] }
  source_ranges = ["0.0.0.0/0"]                 # 🔴 SSH from internet!
}

# 🔴 BAD: RDP from internet (CIS 3.7)
resource "google_compute_firewall" "rdp_all" {
  name    = "allow-rdp-all"
  network = "default"
  allow { protocol = "tcp"; ports = ["3389"] }
  source_ranges = ["0.0.0.0/0"]                 # 🔴 RDP from internet!
}

# =============================================================================
# 🔴 SERVICE ACCOUNT – Owner Role, Key Created, Domain-Wide Delegation
# CIS 1.5: No SA should have admin or owner roles
# CIS 1.6: SA keys should be rotated every 90 days
# =============================================================================
resource "google_service_account" "app_sa" {
  account_id   = "tigergate-app"
  display_name = "TigerGate Application SA"
}

# 🔴 CRITICAL: Owner role = full project control
resource "google_project_iam_binding" "owner_sa" {
  project = "tigergate-prod-99999"
  role    = "roles/owner"                      # 🔴 CIS 1.5: God mode!
  members = ["serviceAccount:${google_service_account.app_sa.email}"]
}

# 🔴 BAD: Long-lived SA key created (should use Workload Identity Federation)
resource "google_service_account_key" "app_sa_key" {
  service_account_id = google_service_account.app_sa.name
  # BAD: No expiry, no rotation — if leaked, attacker has permanent owner access
}

# =============================================================================
# 🔴 BIGQUERY – Public Dataset
# CIS 7.1: BigQuery datasets should not be publicly accessible
# =============================================================================
resource "google_bigquery_dataset" "public_analytics" {
  dataset_id = "tigergate_analytics"
  access {
    role          = "READER"
    special_group = "allUsers"               # 🔴 Anyone can read BigQuery data!
  }
  access {
    role          = "WRITER"
    special_group = "allAuthenticatedUsers"  # 🔴 All Google users can write!
  }
  # BAD: No default encryption key (uses Google-managed, not customer-managed)
  delete_contents_on_destroy = true          # BAD: Accidental terraform destroy deletes all data
}

# =============================================================================
# 🔴 GCP CLOUD SQL – No SSL, No Authorized Networks Restriction
# CIS 6.1: Cloud SQL require_ssl should be enabled
# CIS 6.2: No authorized networks set to 0.0.0.0/0
# =============================================================================
resource "google_sql_database_instance" "main" {
  name             = "tigergate-mysql"
  database_version = "MYSQL_5_7"             # BAD: MySQL 5.7 EOL
  region           = "us-central1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      require_ssl = false                    # 🔴 CIS 6.1: Connections not encrypted!
      authorized_networks {
        value = "0.0.0.0/0"                 # 🔴 CIS 6.2: DB accessible from internet!
        name  = "all"
      }
    }
    backup_configuration {
      enabled = false                         # BAD: No automated backups!
    }
  }
  deletion_protection = false                 # BAD: Can be deleted accidentally
}

output "sa_private_key" {
  value     = google_service_account_key.app_sa_key.private_key
  sensitive = false   # 🔴 CRITICAL: SA private key in terraform output, not marked sensitive!
}
output "cloudsql_connection" {
  value = google_sql_database_instance.main.connection_name
}
