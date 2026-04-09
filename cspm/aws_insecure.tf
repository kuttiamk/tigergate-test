provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "public_bucket" {
  bucket = "tigergate-test-public-bucket"
  acl    = "public-read"
}
resource "aws_db_instance" "unencrypted_rds" {
  allocated_storage    = 10
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "password123"
  storage_encrypted    = false # CSPM alert
  publicly_accessible  = true  # CSPM alert
}
