provider "aws" {
  region = "us-east-1"
}

# 1. Publicly Exposed Insecure EC2
resource "aws_instance" "public_ec2" {
  ami                         = "ami-0abcd1234567890ef"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.overly_permissive_profile.name
  vpc_security_group_ids      = [aws_security_group.allow_all.id]
}

# 2. Allow All Internet Traffic
resource "aws_security_group" "allow_all" {
  name        = "allow-all-sg"
  description = "Open to the world"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Flawed IAM Profile attached to EC2
resource "aws_iam_role" "ec2_role" {
  name = "ec2-over-privileged-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "db_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_iam_instance_profile" "overly_permissive_profile" {
  name = "over-privileged-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# 4. Internal RDS Instance holding PII that the public EC2 can compromise
resource "aws_db_instance" "internal_rds" {
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "password123"
  storage_encrypted = false
}

# TigerGate Attack Path Graph:
# Internet (0.0.0.0/0) -> public_ec2 -> ec2-over-privileged-role -> internal_rds
