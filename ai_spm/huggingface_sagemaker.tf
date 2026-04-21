# =============================================================================
# ai_spm/huggingface_sagemaker.tf - TigerGate CNAPP Test: AI-SPM IaC
# =============================================================================
# PURPOSE: Simulates an insecure AI/ML environment deployment on AWS SageMaker.
#
# TIGERGATE AI-SPM DETECTIONS MATCHING OWASP MACHINE LEARNING:
#   ML01: Sagmaker Endpoint deployed without encryption at rest
#   ML02: Notebook instances internet-enabled and root-accessible
#   ML03: Unencrypted training data bucket
# =============================================================================

resource "aws_sagemaker_notebook_instance" "insecure_notebook" {
  name          = "tigergate-ai-research-notebook"
  role_arn      = aws_iam_role.sagemaker_role.arn
  instance_type = "ml.t2.medium"

  # 🔴 VULN: ML02 - Notebook exposed Directly to the Internet
  direct_internet_access = "Enabled"
  
  # 🔴 VULN: Root Access is enabled by default in SageMaker (Violation in high sec)
  root_access = "Enabled"

  # 🔴 VULN: ML01 - Not encrypted with a CMK
  kms_key_id = "" 
}

resource "aws_s3_bucket" "training_data" {
  # 🔴 VULN: ML03 - Contains sensitive training data (DSPM crossover) without encryption
  bucket = "tigergate-llm-training-data-public"
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.training_data.id
  # 🔴 VULN: Publicly accessible training data
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_sagemaker_model" "huggingface_model" {
  name               = "insecure-huggingface-model"
  execution_role_arn = aws_iam_role.sagemaker_role.arn

  primary_container {
    # 🔴 VULN: Pulling untrusted model image without scanning (Supply Chain / SCA)
    image = "763104351884.dkr.ecr.us-east-1.amazonaws.com/huggingface-pytorch-inference:latest"
  }
}
