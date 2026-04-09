provider "oci" {
  region = "us-phoenix-1"
}
resource "oci_core_volume" "unencrypted_block" {
  availability_domain = "Xyz:PHX-AD-1"
  compartment_id      = "ocid1.compartment.oc1..xxxx"
  # Missing kms_key_id for CMEK encryption
}
