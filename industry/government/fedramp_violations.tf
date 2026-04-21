# =============================================================================
# industry/government/fedramp_violations.tf – TigerGate CNAPP: Government
# =============================================================================
# PURPOSE: Terraform demonstrating FedRAMP Moderate baseline control violations.
# Triggers CSPM findings specific to US federal government cloud compliance.
#
# FEDRAMP CONTROL VIOLATIONS:
#   FED-001: AC-2 / AC-17 – No MFA for remote access (NIST 800-53)
#   FED-002: AU-2 – CloudTrail missing for all management events
#   FED-003: SC-8 – Data in transit not encrypted (TLS 1.2+ required)
#   FED-004: SC-28 – Data at rest not using FIPS 140-2 validated encryption
#   FED-005: CM-7 – Unnecessary ports/services enabled (22, 3389 open)
#   FED-006: IA-5 – Password complexity not enforced (no password policy)
#   FED-007: SA-22 – Unsupported software in use (EOL OS/runtime)
# =============================================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-gov-west-1"   # GovCloud region — FedRAMP Moderate boundary
  # 🔴 FED-001: Static credentials instead of instance profile/IAM role
  access_key = "AKIAIOSFODNN7EXAMPLE"         # BAD: Hardcoded!
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # BAD!
}

# ── FED-004: Primary Data Store without FIPS 140-2 Key Management ───────────
resource "aws_s3_bucket" "gov_data" {
  bucket = "fedramp-moderate-agency-data"
  # 🔴 FED-004: No SSE-KMS with FIPS 140-2 validated key (FedRAMP requires it)
  # 🔴 FED-001: No public access block — Controlled Unclassified Info (CUI) exposed!
  tags = {
    DataClassification = "CUI"       # Tag says CUI but no enforcement!
    FedRAMP            = "Moderate"
  }
}

resource "aws_s3_bucket_policy" "gov_data_policy" {
  bucket = aws_s3_bucket.gov_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"                # 🔴 FED: CUI accessible to anonymous public!
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.gov_data.arn}/*"
    }]
  })
}

# ── FED-007: EC2 Instance with End-of-Life Operating System ─────────────────
resource "aws_instance" "gov_workload" {
  ami           = "ami-0abcdef1234567890"   # Windows Server 2012 R2 (EOL Oct 2023)
  instance_type = "t3.medium"

  # 🔴 FED-005: SSH and RDP open to 0.0.0.0/0 (CM-7: unnecessary services)
  vpc_security_group_ids = [aws_security_group.gov_sg.id]

  # 🔴 FED-004: No encrypted EBS volume
  root_block_device {
    volume_type = "gp3"
    encrypted   = false   # 🔴 BAD: Unencrypted root disk for FedRAMP workload
  }

  # 🔴 FED-001: User data contains hardcoded admin credentials
  user_data = <<-EOF
    <powershell>
    net user Administrator FedAdmin123! /active:yes
    net localgroup administrators backdoor_admin /add
    # 🔴 FED-006: Weak password, no complexity enforcement
    # 🔴 FED-001: No MFA for administrator account
    </powershell>
  EOF

  tags = {
    OS             = "Windows Server 2012 R2"  # 🔴 FED-007: EOL OS!
    Classification = "CUI"
  }
}

# ── FED-005: Insecure Security Group ────────────────────────────────────────
resource "aws_security_group" "gov_sg" {
  name = "fedramp-workload-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 🔴 FED-005: SSH from everywhere violates CM-7
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 🔴 FED-005: RDP from everywhere!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── FED-002: CloudTrail Missing Management Events ────────────────────────────
resource "aws_cloudtrail" "gov_trail" {
  name                          = "fedramp-audit-trail"
  s3_bucket_name                = aws_s3_bucket.gov_data.bucket  # 🔴 Audit in public bucket!
  include_global_service_events = false  # 🔴 FED-002: IAM events not captured!
  is_multi_region_trail         = false  # 🔴 Other regions unaudited!
  enable_log_file_validation    = false  # 🔴 Log tampering not detectable

  # 🔴 FED-002: No event selectors — management events NOT captured
}

# ── FED-003: Load Balancer with Weak TLS Policy ──────────────────────────────
resource "aws_lb_listener" "gov_https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-gov-west-1:123456789012:loadbalancer/app/gov-lb/abc123"
  port              = 443
  protocol          = "HTTPS"
  # 🔴 FED-003: TLS 1.0/1.1 allowed — FedRAMP requires TLS 1.2+ minimum
  ssl_policy = "ELBSecurityPolicy-2016-08"  # Allows TLS 1.0 — deprecated!
  certificate_arn   = "arn:aws:acm:us-gov-west-1:123456789012:certificate/abc"
  default_action {
    type = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-gov-west-1:123456789012:targetgroup/gov/abc"
  }
}

# ── FED-006: No IAM Password Policy ─────────────────────────────────────────
# 🔴 FED-006: Omitting aws_iam_account_password_policy means AWS default (8 char min, no complexity)
# FedRAMP requires 12+ chars, uppercase, lowercase, numbers, symbols per NIST 800-63B
