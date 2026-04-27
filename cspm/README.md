# 📁 `cspm/` — Cloud Security Posture Management

## What Is This?

CSPM tools scan your **cloud configuration** (how you set up AWS, Azure, GCP, Oracle)
to find settings that are insecure — like a publicly readable S3 bucket or a database
port accidentally exposed to the internet.

## What's In This Folder?

| File | Cloud | What It Does |
|------|-------|-------------|
| `aws_insecure.tf` | AWS | 20+ CIS AWS Benchmark v1.5.0 violations |
| `azure_insecure.tf` | Azure | 16+ CIS Azure 1.5.0 violations |
| `gcp_insecure.tf` | GCP | 12+ CIS GCP 1.3.0 violations |

## Simple Example — What a Misconfiguration Looks Like

```hcl
# ❌ BAD — S3 bucket open to the public internet
resource "aws_s3_bucket" "data" {
  bucket = "megacorp-user-data"
  acl    = "public-read"   # 🔴 Anyone can download your data!
}

# ✅ GOOD — S3 bucket locked down
resource "aws_s3_bucket" "data" {
  bucket = "megacorp-user-data"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Which Scanners Catch These?
- **Checkov** (`make scan-checkov`) — finds Terraform misconfigs
- **tfsec** (`make scan-tfsec`) — another Terraform scanner
- **TigerGate CSPM** — cloud-connected real-time detection

## Learn More
- [CIS AWS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
- [GLOSSARY.md](../GLOSSARY.md) → look up: CSPM, IAM, S3
