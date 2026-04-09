resource "aws_sagemaker_endpoint_configuration" "hf_endpoint" {
  name = "huggingface-inference-endpoint"
  production_variants {
    variant_name           = "AllTraffic"
    model_name             = "huggingface-model"
    initial_instance_count = 1
    instance_type          = "ml.m4.xlarge"
  }
  # Missing KMS keys for data at rest
  # Missing VPC config for network isolation
}
