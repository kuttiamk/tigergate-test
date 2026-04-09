resource "aws_db_instance" "pii_database" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "password123"
  storage_encrypted = false
  tags = {
    DataClassification = "PII"
    Compliance         = "HIPAA"
  }
}
