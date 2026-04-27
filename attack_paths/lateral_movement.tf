# =============================================================================
# attack_paths/lateral_movement.tf - TigerGate CNAPP Test: Attack Path Analysis
# =============================================================================
# PURPOSE: Demonstrates a realistic "Toxic Combination" / Attack Path.
# TigerGate's Exposure Analysis should correlate these misconfigurations.
#
# ATTACK PATH:
# 1. 🌐 Publicly exposed EC2 instance (Port 80/22 open to 0.0.0.0/0)
# 2. 💻 EC2 instance has critical vulnerabilities (e.g., Log4Shell or out-of-date Apache)
# 3. 🔑 EC2 instance has an overly permissive IAM Instance Profile (CIEM)
# 4. 🗄️ IAM Profile grants access to S3 Bucket containing sensitive PII (DSPM)
# RESULT: Critical "Internet to Sensitive Data" path.
# =============================================================================

# 1. PUBLIC EXPOSURE -> Security Group allowing internet ingress
resource "aws_security_group" "public_sg" {
  name        = "public_facing_sg"
  description = "Allows public access"
  
  # 🔴 VULN: 0.0.0.0/0 exposure
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. VULNERABLE WORKLOAD -> EC2 instance (Simulated via tag, would be detected by CWPP Agent)
resource "aws_instance" "vulnerable_app_server" {
  ami           = "ami-0abcdef1234567890" # Pretend this is an old unpatched image
  instance_type = "t2.micro"
  
  vpc_security_group_ids = [aws_security_group.public_sg.id]
  # 🔴 VULN: Assigns the overly permissive IAM role to the public workload
  iam_instance_profile   = aws_iam_instance_profile.overly_permissive_profile.name
  
  tags = {
    Name = "Vulnerable-Web-App"
    Known_CVE = "CVE-2021-44228" # Log4Shell mock
  }
}

# 3. LATERAL MOVEMENT / PRIVILEGE ESCALATION -> CIEM Over-permissions
resource "aws_iam_role" "app_server_role" {
  name = "app_server_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "s3_full_access" {
  name = "s3_full_access"
  role = aws_iam_role.app_server_role.id
  # 🔴 VULN: EC2 instance is granted direct administrative access to the PII bucket
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
      Resource = [
        aws_s3_bucket.sensitive_pii_bucket.arn,
        "${aws_s3_bucket.sensitive_pii_bucket.arn}/*"
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "overly_permissive_profile" {
  name = "app_server_profile"
  role = aws_iam_role.app_server_role.name
}

# 4. SENSITIVE DATA -> DSPM Target
resource "aws_s3_bucket" "sensitive_pii_bucket" {
  bucket = "tigergate-customer-pii-data" # 🔴 VULN: Contains PII/PHI (Flagged by DSPM)
}
