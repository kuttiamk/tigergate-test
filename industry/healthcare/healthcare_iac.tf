# =============================================================================
# industry/healthcare/healthcare_iac.tf – TigerGate CNAPP: Healthcare IaC
# =============================================================================
# PURPOSE: Terraform for a healthcare environment with HIPAA infrastructure
# violations. PHI ends up in public S3, CloudTrail doesn't capture PHI access,
# and the EHR database is publicly reachable.
#
# HIPAA IaC VIOLATIONS:
#   H-IaC-001: §164.312(a)(2)(iv) – PHI S3 bucket not encrypted at rest
#   H-IaC-002: §164.308(a)(1)(ii)(D) – No CloudTrail for PHI data access
#   H-IaC-003: §164.312(e)(1) – Data in transit not protected (HTTP endpoint)
#   H-IaC-004: §164.308(a)(5)(ii)(C) – No automatic logoff / session limits
#   H-IaC-005: §164.308(a)(7) – No DR plan: RDS with no backup or multi-AZ
# =============================================================================

terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}

provider "aws" { region = "us-east-1" }

# ── H-IaC-001: PHI S3 Bucket – Unencrypted, No Access Logging ───────────────
resource "aws_s3_bucket" "phi_storage" {
  bucket = "megacorp-patient-records-phi-prod"
  # 🔴 H-IaC-001: No server-side encryption (PHI must be encrypted at rest per HIPAA)
  tags = { DataClassification = "PHI", HIPAA = "true" }  # Tagged but not protected!
}

# 🔴 H-IaC-001: No SSE-KMS (aws_s3_bucket_server_side_encryption_configuration missing)
# 🔴 H-IaC-002: No S3 access logging (PHI access unaudited)
# (aws_s3_bucket_logging missing)

resource "aws_s3_bucket_acl" "phi_acl" {
  bucket = aws_s3_bucket.phi_storage.id
  acl    = "public-read"   # 🔴 H-IaC-001: PHI data readable by anonymous public!
}

# ── H-IaC-005: EHR Database – No Backup, No Multi-AZ, Publicly Accessible ───
resource "aws_db_instance" "ehr_db" {
  identifier          = "megacorp-ehr-prod"
  engine              = "mysql"
  engine_version      = "5.7"              # 🔴 EOL MySQL 5.7 (EOL Oct 2023)
  instance_class      = "db.t3.medium"
  db_name             = "ehr_production"
  username            = "root"             # 🔴 Root DB user — no least privilege
  password            = "HipaaAdmin@123"  # 🔴 Hardcoded password
  allocated_storage   = 100
  storage_encrypted   = false             # 🔴 H-IaC-001: PHI DB not encrypted!
  publicly_accessible = true              # 🔴 EHR database accessible from internet!
  multi_az            = false             # 🔴 H-IaC-005: No HA for PHI system
  backup_retention_period = 0            # 🔴 H-IaC-005: No backups!
  skip_final_snapshot = true             # 🔴 Database can be lost permanently
  deletion_protection = false
}

# ── H-IaC-002: CloudTrail Without Data Events for PHI Bucket ─────────────────
resource "aws_cloudtrail" "healthcare_trail" {
  name           = "healthcare-audit"
  s3_bucket_name = aws_s3_bucket.phi_storage.bucket  # 🔴 Audit logs in public PHI bucket!
  enable_log_file_validation = false                  # 🔴 Log tampering undetectable
  is_multi_region_trail      = false

  # 🔴 H-IaC-002: No event_selector for data events — S3 GetObject on PHI NOT audited
  # HIPAA requires tracking WHO accessed PHI data, WHEN, and WHAT they accessed
  # Missing:
  # event_selector {
  #   read_write_type           = "All"
  #   include_management_events = true
  #   data_resource {
  #     type   = "AWS::S3::Object"
  #     values = ["${aws_s3_bucket.phi_storage.arn}/"]
  #   }
  # }
}

# ── H-IaC-003: Application Security Group (HTTP, Not HTTPS) ─────────────────
resource "aws_security_group" "ehr_app_sg" {
  name = "ehr-application-sg"

  # 🔴 H-IaC-003: HTTP port 80 open — PHI transmitted in plaintext!
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # 🔴 Open to world on HTTP
  }
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # 🔴 MySQL port exposed to internet!
  }
  egress {
    from_port = 0; to_port = 0; protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
