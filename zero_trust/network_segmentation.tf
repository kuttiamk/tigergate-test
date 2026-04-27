# =============================================================================
# zero_trust/network_segmentation.tf – TigerGate CNAPP: Zero Trust Architecture
# =============================================================================
# PURPOSE: Demonstrates violations of Zero Trust Network Architecture (ZTNA)
# principles in a cloud environment. Shows implicit trust zones that Zero Trust
# eliminates.
#
# ZERO TRUST VIOLATIONS (NIST SP 800-207):
#   ZT-001: Implicit trust based on network location (VPC membership = trusted)
#   ZT-002: Overly broad network segments (no micro-segmentation)
#   ZT-003: No continuous verification for internal resources
#   ZT-004: Credentials not rotated or short-lived (long-lived static keys)
#   ZT-005: No device posture validation before resource access
# =============================================================================

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

# ── ZT-001/002: Flat Network — No Micro-Segmentation ────────────────────────
# 🔴 ZT-001: Single large VPC grants implicit trust to all workloads
# 🔴 ZT-002: No subnet segmentation between app tiers (web, app, db in same subnet)
resource "aws_vpc" "flat_network" {
  cidr_block           = "10.0.0.0/8"   # 🔴 ZT-002: /8 = 16 million IPs in one trust zone
  enable_dns_hostnames = true
  tags = { Name = "flat-no-segmentation-vpc" }
}

# 🔴 ZT-002: All services in one subnet — no isolation between tiers
resource "aws_subnet" "everything_together" {
  vpc_id            = aws_vpc.flat_network.id
  cidr_block        = "10.0.0.0/8"      # 🔴 ZT-002: Entire VPC in one subnet!
  map_public_ip_on_launch = true        # 🔴 ZT: All instances get public IPs
}

# ── ZT-001: "If you're in the VPC, you're trusted" Security Group ─────────
resource "aws_security_group" "internal_trusted" {
  vpc_id = aws_vpc.flat_network.id
  name   = "internal-trusted-zone"

  # 🔴 ZT-001: Any resource inside VPC can talk to any other — IMPLICIT TRUST!
  # Zero Trust requires explicit allow lists per-service, per-port
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # 🔴 ZT-001: "Internal = Trusted" is anti-Zero Trust
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]   # 🔴 ZT-001: All UDP traffic trusted internally too!
  }
}

# ── ZT-003: Long-Lived Static Credentials (No Rotation) ─────────────────────
# 🔴 ZT-003: IAM user with static credentials (no short-lived role assumption)
resource "aws_iam_user" "service_account" {
  name = "app-service-account"
  # 🔴 ZT-004: Static IAM user key — Zero Trust requires short-lived tokens
  # Should use: EC2 instance profile, EKS IRSA, or AWS SSO with session duration limits
}

resource "aws_iam_access_key" "service_key" {
  user   = aws_iam_user.service_account.name
  # 🔴 ZT-004: Access key never expires — valid indefinitely until manually rotated
  # Zero Trust: All credentials should be time-limited (NIST 800-207 §3.3)
}

resource "aws_iam_user_policy" "service_policy" {
  name = "service-permissions"
  user = aws_iam_user.service_account.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:*", "rds:*", "dynamodb:*"]  # 🔴 ZT-003: No least privilege
      Resource = "*"                                          # 🔴 All resources accessible
    }]
  })
}

# ── ZT-005: No Endpoint/Device Posture Validation ───────────────────────────
# Zero Trust requires device health checks before access (MDM enrollment,
# OS patch level, EDR presence, disk encryption status)
#
# 🔴 ZT-005: Missing AWS Verified Access configuration (device posture)
# 🔴 ZT-005: No Client VPN with mutual TLS certificate authentication
# 🔴 ZT-005: No AWS Network Firewall between service tiers
# 🔴 ZT-005: No VPC Endpoint Policies (S3/DynamoDB accessible without device check)

# Represents what's MISSING — no VerifiedAccess, no Network Firewall, no endpoint policies
output "zero_trust_gaps" {
  value = {
    # 🔴 All of these SHOULD exist in a Zero Trust architecture
    micro_segmentation     = "MISSING"
    device_posture_check   = "MISSING"
    continuous_verification = "MISSING"
    short_lived_credentials = "MISSING"
    service_mesh_mtls      = "MISSING"
    network_firewall       = "MISSING"
  }
}
