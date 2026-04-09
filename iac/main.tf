provider "aws" {
  region = "us-east-1"
}

# Vulnerability 1: Hardcoded AWS keys in Terraform
variable "aws_access_key" {
  default = "AKIAIOSFODNN7EXAMPLE"
}

# Vulnerability 2: S3 bucket publicly readable
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-12345"
  acl    = "public-read"
}

# Vulnerability 3: Security group with open inbound rules
resource "aws_security_group" "open_ssh" {
  name        = "allow_ssh_from_anywhere"
  description = "Vuln SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
