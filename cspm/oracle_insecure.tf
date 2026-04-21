# =============================================================================
# cspm/oracle_insecure.tf – TigerGate CNAPP Test: OCI (Oracle Cloud) Misconfigurations
# =============================================================================
# PURPOSE: Demonstrates Oracle Cloud Infrastructure (OCI) security violations.
#
# ⚠️ EDUCATIONAL USE ONLY — Do not deploy this Oracle infrastructure.
#
# TIGERGATE CSPM DETECTIONS MATCHING CIS ORACLE CLOUD FOUNDATIONS BENCHMARK v1.2.0:
#   OCI-001: IAM - User has API keys associated (CIS 1.2.0 #1.3)
#   OCI-002: IAM - Passwords must enforce complexity (CIS 1.2.0 #1.7)
#   OCI-003: Net - Default security list allows inbound from 0.0.0.0/0 (CIS 1.2.0 #2.1)
#   OCI-004: Obj - Object Storage bucket is publicly visible (CIS 1.2.0 #3.1)
#   OCI-005: Obj - Object Storage bucket without versioning (CIS 1.2.0 #3.2)
#   OCI-006: Blk - Block volume not encrypted with Customer Managed Key (CIS 1.2.0 #4.1)
# =============================================================================

provider "oci" {
  region       = "us-ashburn-1"
  # 🔴 VULN: Hardcoded credentials
  tenancy_ocid = "ocid1.tenancy.oc1..aaaaaaaadummy"
  user_ocid    = "ocid1.user.oc1..aaaaaaaadummy"
  fingerprint  = "20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:00:11"
  private_key  = "-----BEGIN RSA PRIVATE KEY-----\ndummy\n-----END RSA PRIVATE KEY-----"
}

# =============================================================================
# 🔴 OBJECT STORAGE (DSPM Exposure)
# CIS 1.2.0 Section 3.1: Ensure Object Storage Buckets are not public
# =============================================================================
resource "oci_objectstorage_bucket" "insecure_bucket" {
  compartment_id = var.compartment_id
  name           = "tigergate-public-assets"
  namespace      = data.oci_objectstorage_namespace.ns.namespace
  
  # 🔴 VULN: Bucket is anonymously accessible! (Data Leakage)
  access_type = "ObjectReadWithoutDirectoryListing" # Allows anonymous GETs!
  
  # 🔴 VULN: Default encryption instead of Customer Managed Key (CMK)
  kms_key_id = "" 
  
  # 🔴 VULN: CIS 3.2 - Versioning is disabled (Ransomware risk)
  versioning = "Disabled"
}

# =============================================================================
# 🔴 NETWORKING (Exposure Analysis)
# CIS 1.2.0 Section 2.1: Ensure no security lists allow ingress from 0.0.0.0/0 to port 22 or 3389
# =============================================================================
resource "oci_core_security_list" "insecure_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main_vcn.id
  display_name   = "InsecureSecurityList"

  # 🔴 VULN: Internet exposed RDP (CIS 2.2) and SSH (CIS 2.1)
  ingress_security_rules {
    protocol    = "6" # TCP
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    description = "Allow SSH and RDP from anywhere"
    tcp_options {
      min = 22
      max = 3389
    }
  }

  # 🔴 VULN: Internet exposed database port
  ingress_security_rules {
    protocol    = "6"
    source      = "0.0.0.0/0"
    tcp_options {
      min = 1521
      max = 1521
    }
  }
}

# =============================================================================
# 🔴 COMPUTE & BLOCK STORAGE
# CIS 1.2.0 Section 4.1: Block Volumes Customer Managed Keys
# =============================================================================
resource "oci_core_instance" "insecure_vm" {
  compartment_id      = var.compartment_id
  availability_domain = "AD-1"
  shape               = "VM.Standard2.1"

  create_vnic_details {
    subnet_id        = oci_core_subnet.public_subnet.id
    # 🔴 VULN: Automatically assigns public IP address
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    source_id   = var.image_id
  }

  metadata = {
    # 🔴 VULN: Hardcoded init script containing database passwords (DSPM risk)
    user_data = base64encode(<<EOF
#!/bin/bash
echo "export DB_PASS=supersecret_oci_db_pass" >> /etc/environment
apt-get update && apt-get install -y oracle-database-client
EOF
    )
  }
}

resource "oci_core_volume" "insecure_volume" {
  compartment_id      = var.compartment_id
  availability_domain = "AD-1"
  
  # 🔴 VULN: Missing kms_key_id defaults to Oracle managed key instead of CMK
  # kms_key_id = oci_kms_key.my_key.id
}

# =============================================================================
# 🔴 IDENTITY & ACCESS MANAGEMENT (CIEM)
# CIS 1.2.0 Section 1: IAM Policies & Authentication
# =============================================================================
resource "oci_identity_policy" "over_permissive" {
  compartment_id = var.compartment_id
  description    = "Overly permissive policy"
  name           = "allow_all_manage"
  
  # 🔴 VULN: Action:* / Resource:* equivalent in OCI
  statements = [
    "Allow group Administrators to manage all-resources IN TENANCY"
  ]
}

resource "oci_identity_authentication_policy" "weak_passwords" {
  compartment_id = var.tenancy_ocid
  
  password_policy {
    # 🔴 VULN: Weak password policy (CIS 1.7)
    minimum_password_length   = 6
    is_lowercase_characters_required = false
    is_uppercase_characters_required = false
    is_numeric_characters_required   = false
    is_special_characters_required   = false
  }
}
