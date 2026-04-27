# =============================================================================
# industry/startup/rapid_deploy.tf – TigerGate CNAPP: Startup Industry
# =============================================================================
# PURPOSE: Common startup anti-patterns — moving fast with no security guardrails.
# Demonstrates the typical "MVP first, security later" posture that creates
# massive attack surface as the company scales.
#
# STARTUP SECURITY ANTI-PATTERNS:
#   SU-001: Root account used for everything (no IAM users or roles)
#   SU-002: No VPC — everything deployed in default VPC (public subnets)
#   SU-003: No MFA on root or any account
#   SU-004: S3 buckets for everything — public by default for "ease of access"
#   SU-005: Environment variables for all secrets (no Vault, SSM, or Secrets Manager)
#   SU-006: Debug mode forever — "We'll disable it before launch"
#   SU-007: No backup, no disaster recovery, no multi-AZ
# =============================================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  # 🔴 SU: No remote state — terraform.tfstate stored locally, committed to git!
}

provider "aws" {
  region = "us-east-1"
  # 🔴 SU-001: Root account credentials hardcoded — startup founder uses root for everything
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ── SU-002/004: "Just make it public so the frontend can access it" ──────────
resource "aws_s3_bucket" "startup_assets" {
  bucket = "startupxyz-user-uploads-production"
  # 🔴 SU-004: Public bucket for user uploads including potential PII
}

resource "aws_s3_bucket_acl" "startup_acl" {
  bucket = aws_s3_bucket.startup_assets.id
  acl    = "public-read-write"   # 🔴 BAD: Users can write to production bucket!
}

# ── SU-006: Single monolith EC2 with debug mode ──────────────────────────────
resource "aws_instance" "startup_monolith" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"      # 🔴 SU: t2 (burstable) for production — CPU starvation
  key_name      = "founder-laptop-key"  # 🔴 SU: Shared team key from founder's laptop

  # 🔴 SU-002: Deployed to default VPC (public subnet, no private network)

  # 🔴 SU-005/006: All configuration as environment variable (no secrets mgmt)
  user_data = <<-EOF
    #!/bin/bash
    export NODE_ENV=production
    export DEBUG=true                                           # 🔴 Debug forever!
    export DB_URL="mongodb://admin:Password123@localhost/prod"  # 🔴 Hardcoded!
    export JWT_SECRET="supersecret"                            # 🔴 Weak + hardcoded!
    export STRIPE_KEY="STRIPE_LIVE_EXAMPLE_TEST_KEY_NOT_REAL"     # 🔴 Live key in userdata!
    export SENDGRID_KEY="SG.AAAAAA.bbbbbbbbbbbbbbbbbbb"       # 🔴 Hardcoded!
    cd /app && npm start &
  EOF

  # 🔴 SU: No IAM instance profile — app runs with no permissions (or as root user)
  # iam_instance_profile = "..."   << Not set!
  tags = { Name = "prod-server-v1" }   # 🔴 SU: Entire production in 1 instance!
}

# ── SU: Security Group that is "temporary" (and never changed) ───────────────
resource "aws_security_group" "startup_sg" {
  name = "allow-everything-temp"  # 🔴 SU: "temporary" SG that stayed for 3 years
  ingress {
    from_port = 0; to_port = 65535; protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 🔴 ALL PORTS from ALL IPs — "we'll restrict later"
  }
  egress {
    from_port = 0; to_port = 0; protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── SU-007: No RDS backup, single AZ, no encryption ─────────────────────────
resource "aws_db_instance" "startup_db" {
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  identifier           = "startup-prod-db"
  db_name              = "production"
  username             = "root"                  # 🔴 SU: Root DB user
  password             = "Password123"           # 🔴 SU: Weak password, no rotation
  allocated_storage    = 20
  publicly_accessible  = true                    # 🔴 SU: DB visible from internet!
  multi_az             = false                   # 🔴 SU-007: No HA
  backup_retention_period = 0                    # 🔴 SU-007: No backups!
  deletion_protection  = false                   # 🔴 SU: DB can be deleted by anyone with access
  storage_encrypted    = false                   # 🔴 SU: No encryption at rest
  skip_final_snapshot  = true                    # 🔴 SU: No snapshot on delete!
}
