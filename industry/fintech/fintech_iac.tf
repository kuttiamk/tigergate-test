# =============================================================================
# industry/fintech/fintech_iac.tf – TigerGate CNAPP: FinTech IaC Security
# =============================================================================
# PURPOSE: Terraform configurations for a FinTech environment with intentional
# PCI-DSS and CIS AWS violations in the infrastructure layer.
#
# PCI-DSS IaC VIOLATIONS:
#   PCI-IaC-001: Req 3.5 – Payment database not using encryption at rest
#   PCI-IaC-002: Req 4.2 – Payment API endpoint accepts non-TLS traffic
#   PCI-IaC-003: Req 1.3 – Network ACL allows inbound unrestricted access
#   PCI-IaC-004: Req 10.5 – S3 bucket for financial records has no access logging
#   PCI-IaC-005: Req 7.1 – IAM role for payment processor has wildcard S3 access
# =============================================================================

terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}

provider "aws" { region = "us-east-1" }

# ── PCI-IaC-001: Unencrypted Payment Database ────────────────────────────────
resource "aws_db_instance" "payment_db" {
  identifier          = "megacorp-payments-prod"
  engine              = "postgres"
  engine_version      = "13.4"
  instance_class      = "db.m5.large"
  db_name             = "payments"
  username            = "paymentadmin"
  password            = "PciProd@2024!"   # 🔴 PCI: Hardcoded DB credentials
  allocated_storage   = 100

  # 🔴 PCI-IaC-001: Database storing PAN/CVV data NOT encrypted at rest
  storage_encrypted   = false   # PCI Req 3.5: Must encrypt cardholder data at rest!

  # 🔴 PCI-IaC-002: Publicly accessible payment DB
  publicly_accessible = true    # PCI Req 1.3: Restrict inbound connectivity

  # 🔴 No multi-AZ for payment system (availability risk for PCI)
  multi_az            = false
  backup_retention_period = 0   # 🔴 No backups on payment database!
  deletion_protection = false   # 🔴 DB can be accidentally deleted!
  skip_final_snapshot = true
}

# ── PCI-IaC-004: Financial Records S3 Bucket without logging ─────────────────
resource "aws_s3_bucket" "financial_records" {
  bucket = "megacorp-financial-records-prod"
  # 🔴 PCI-IaC-004: No access logging — cannot audit who accessed cardholder data
}

resource "aws_s3_bucket_versioning" "financial_ver" {
  bucket = aws_s3_bucket.financial_records.id
  versioning_configuration {
    status = "Disabled"   # 🔴 PCI: No versioning — records can be overwritten/deleted
  }
}

# 🔴 PCI-IaC-001: No SSE-KMS on financial records bucket
# (Missing aws_s3_bucket_server_side_encryption_configuration)

# 🔴 PCI-IaC-003: Public access block NOT configured — defaults are permissive
# (Missing aws_s3_bucket_public_access_block)

# ── PCI-IaC-005: Overpermissioned Payment Processor IAM Role ─────────────────
resource "aws_iam_role" "payment_processor" {
  name = "payment-processor-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "payment_policy" {
  name = "payment-processor-policy"
  role = aws_iam_role.payment_processor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 🔴 PCI-IaC-005: Wildcard S3 access — can read ALL buckets including non-PCI
        Effect   = "Allow"
        Action   = ["s3:*"]         # 🔴 PCI Req 7.1: Not least-privilege!
        Resource = "*"              # 🔴 All S3 buckets — massive PCI scope expansion
      },
      {
        # 🔴 Full RDS access enables reading all databases, not just payment
        Effect   = "Allow"
        Action   = ["rds:*"]
        Resource = "*"
      }
    ]
  })
}

# ── PCI-IaC-002: HTTP Load Balancer (no HTTPS enforcement) ───────────────────
resource "aws_lb_listener" "payment_http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/payments/abc"
  port              = 80   # 🔴 PCI-IaC-002: HTTP listener on payment system!
  protocol          = "HTTP"
  # Should redirect to HTTPS; instead it serves payment traffic in plaintext
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/pay/xyz"
  }
}
