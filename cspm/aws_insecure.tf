# =============================================================================
# cspm/aws_insecure.tf – TigerGate CNAPP Test: Comprehensive AWS CSPM Misconfigs
# =============================================================================
# PURPOSE: Intentionally misconfigured AWS Terraform for CSPM testing.
# Tigergate CSPM scans IaC to find deviations from CIS AWS Benchmark.
#
# CSPM RULES TRIGGERED (CIS AWS Benchmark):
#   CIS 2.1.1 – S3 bucket access control not restricted
#   CIS 2.1.2 – S3 no MFA delete, no versioning
#   CIS 2.2.1 – EBS volumes not encrypted
#   CIS 3.3   – CloudTrail not enabled (no audit logs!)
#   CIS 4.1   – Security group allows all ingress from 0.0.0.0/0
#   CIS 5.2   – GuardDuty not enabled
#   CIS 6.1   – RDS not encrypted, publicly accessible
# =============================================================================

provider "aws" {
  region     = "us-east-1"
  # 🔴 CRITICAL: CWE-798 – Hardcoded credentials in provider block!
  # FIX: Remove access_key/secret_key — use IAM roles, instance profiles, or env vars
  access_key = "AKIAIOSFODNN7EXAMPLE"                          # 🔴 Hardcoded AWS key!
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # 🔴 Hardcoded secret!
}

# =============================================================================
# 🔴 S3 BUCKET – Public, Unencrypted, No Versioning, No Logging
# CIS AWS Benchmark: 2.1.1 (Public Access), 2.1.2 (Encryption), 2.1.3 (Versioning)
# Tigergate CSPM: "S3 buckets should not be publicly accessible"
# =============================================================================
resource "aws_s3_bucket" "public_data" {
  bucket        = "tigergate-public-data-2024"    # BAD: Predictable name with year
  force_destroy = true                             # BAD: Can delete with all data in one command
  tags = { Environment = "production" }            # BAD: Production bucket, 0 security
}

# 🔴 BAD: All block_public_access = false → account-level public exposure
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false   # 🔴 CIS 2.1.1
  block_public_policy     = false   # 🔴 CIS 2.1.1
  ignore_public_acls      = false   # 🔴 CIS 2.1.1
  restrict_public_buckets = false   # 🔴 CIS 2.1.1
}

# 🔴 BAD: Anonymous GET + PUT allowed via bucket policy
resource "aws_s3_bucket_policy" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadWrite"
      Effect    = "Allow"
      Principal = "*"                         # 🔴 Anyone on internet!
      Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]  # 🔴 Write + Delete!
      Resource  = "${aws_s3_bucket.public_data.arn}/*"
    }]
  })
}

# 🔴 BAD: Versioning disabled — deleted files unrecoverable
resource "aws_s3_bucket_versioning" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration { status = "Disabled" }  # 🔴 CIS 2.1.2
}

# No logging — who accessed the bucket? 🤷 (CIS 2.6)
# resource "aws_s3_bucket_logging" { ... }  # ← MISSING!


# =============================================================================
# 🔴 EC2 + SECURITY GROUP – All ports from internet, IMDSv1, unencrypted disk
# CIS 4.1 – Avoid unrestricted inbound access
# CIS 4.2 – No unrestricted SSH from 0.0.0.0/0
# =============================================================================
resource "aws_security_group" "allow_all" {
  name        = "tigergate-allow-all"
  description = "Dev - open to all"   # BAD: Vague description

  # 🔴 BAD: ALL TCP from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535                          # 🔴 Every single port!
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]                 # 🔴 Entire internet!
    description = ""                             # BAD: No rule description
  }
  # 🔴 BAD: SSH explicitly open (CIS 4.2)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]                 # 🔴 SSH from internet!
  }
  # 🔴 BAD: RDP open to internet
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]                 # 🔴 RDP from internet!
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]                 # BAD: Unrestricted data exfiltration
  }
}

resource "aws_instance" "web_server" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t2.micro"
  associate_public_ip_address = true                    # BAD: Public IP directly
  vpc_security_group_ids      = [aws_security_group.allow_all.id]

  # 🔴 BAD: IMDSv1 — SSRF can steal IAM credentials via curl http://169.254.169.254/
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"            # 🔴 CIS 5.6: Should be "required"
    http_put_response_hop_limit = 2                     # BAD: Container workloads can access IMDS
  }

  # 🔴 BAD: Unencrypted root volume (CIS 2.2.1)
  root_block_device {
    encrypted             = false                        # 🔴 CIS 2.2.1!
    delete_on_termination = true
  }

  # 🔴 BAD: Credentials in user data — visible via IMDS or AWS console
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASS="root123"                            # 🔴 Hardcoded in user-data!
    export AWS_SECRET="wJalrXUtnFEMI"                  # 🔴 AWS key in user-data!
    echo "DB connection: mysql://root:$DB_PASS@db:3306" >> /var/log/app.log  # 🔴 Credential in log
  EOF

  tags = { Name = "tigergate-web-server", Environment = "production" }
}

# Additional unencrypted EBS volume
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false          # 🔴 CIS 2.2.1: Must be true in production!
}


# =============================================================================
# 🔴 RDS – Publicly Accessible, No Encryption, No Backups, MySQL 5.7 EOL
# CIS 6.6 – RDS not publicly accessible
# CIS 6.7 – RDS not encrypted
# =============================================================================
resource "aws_db_instance" "main_db" {
  identifier        = "tigergate-prod-db"
  engine            = "mysql"
  engine_version    = "5.7"            # BAD: MySQL 5.7 EOL (Oct 2023)
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "tigergate"
  username          = "admin"
  password          = "Password123!"    # 🔴 Hardcoded DB password!

  publicly_accessible  = true           # 🔴 CIS 6.6 – DB on internet!
  storage_encrypted    = false          # 🔴 CIS 6.7 – No encryption!
  multi_az             = false          # BAD: Single point of failure
  deletion_protection  = false          # BAD: `terraform destroy` = data gone!
  skip_final_snapshot  = true           # BAD: No snapshot before deletion

  backup_retention_period    = 0        # 🔴 Backups disabled!
  auto_minor_version_upgrade = false    # BAD: Known CVEs not patched

  vpc_security_group_ids = [aws_security_group.allow_all.id]  # BAD: Open SG

  # No parameter group enforcing SSL connections (CIS 6.5)
}


# =============================================================================
# 🔴 CLOUDTRAIL DISABLED — No API Audit Logging (CIS 3.1)
# Without CloudTrail, there is NO record of:
# - Who ran what AWS API call
# - What data was accessed or deleted
# - When credentials were used and from where
# FIX: Enable multi-region CloudTrail with S3 + CloudWatch Logs destination
# =============================================================================
# NOTE: CloudTrail resource is INTENTIONALLY MISSING — this is the CSPM finding!
# "aws_cloudtrail" resource not defined anywhere in this config.


# =============================================================================
# 🔴 GUARDDUTY DISABLED (CIS 5.2)
# GuardDuty detects threats like: cryptocurrency mining, compromised EC2,
# data exfiltration, known malicious IPs/domains
# FIX: aws_guardduty_detector { enable = true }
# =============================================================================
# NOTE: aws_guardduty_detector resource INTENTIONALLY MISSING


# =============================================================================
# 🔴 AWS CONFIG DISABLED
# Without Config, there's no continuous compliance monitoring
# FIX: Enable aws_config_configuration_recorder
# =============================================================================
# NOTE: aws_config_configuration_recorder INTENTIONALLY MISSING


output "public_bucket_url" {
  value = "https://${aws_s3_bucket.public_data.bucket}.s3.amazonaws.com"  # BAD: Exposes URL
}
output "rds_endpoint" {
  value = aws_db_instance.main_db.endpoint  # BAD: Exposes DB endpoint
}
output "rds_password" {
  value     = aws_db_instance.main_db.password   # 🔴 CRITICAL: Password in TF output!
  sensitive = false                              # 🔴 Not marked as sensitive!
}
