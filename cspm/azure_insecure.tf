# =============================================================================
# cspm/azure_insecure.tf – TigerGate CNAPP Test: Comprehensive Azure CSPM Misconfigs
# =============================================================================
# CSPM RULES TRIGGERED (CIS Azure Benchmark):
#   CIS 3.1  – Storage account allows public blob access
#   CIS 3.7  – Storage account not using HTTPS-only
#   CIS 3.10 – Storage account using deprecated shared key access
#   CIS 6.1  – NSG allows all inbound traffic from the internet
#   CIS 7.2  – VM disk not encrypted
#   CIS 8.1  – Azure SQL Auditing not enabled
# =============================================================================

provider "azurerm" {
  features {}
  # 🔴 BAD: Hardcoded service principal credentials
  # FIX: Use az login, managed identity, or ARM_* environment variables
  subscription_id = "12345678-1234-1234-1234-123456789abc"  # BAD: Hardcoded
  client_id       = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # BAD: Hardcoded
  client_secret   = "TigergateAzureSecret123!"              # 🔴 Hardcoded secret!
  tenant_id       = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"  # BAD: Hardcoded
}

resource "azurerm_resource_group" "tigergate" {
  name     = "tigergate-resources"
  location = "East US"
}

# =============================================================================
# 🔴 NSG – ALL ports open from internet (CIS 6.1 + 6.2)
# CIS: "Network security group should restrict all traffic"
# CIS: "RDP access from the internet should be blocked"
# CIS: "SSH access from the internet should be blocked"
# =============================================================================
resource "azurerm_network_security_group" "open_all" {
  name                = "tigergate-open-nsg"
  location            = azurerm_resource_group.tigergate.location
  resource_group_name = azurerm_resource_group.tigergate.name

  # 🔴 BAD: Allow ALL inbound traffic from ANY source
  security_rule {
    name                       = "allow-all-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"                # All protocols!
    source_port_range          = "*"
    destination_port_range     = "*"               # ALL ports!
    source_address_prefix      = "*"               # 🔴 Entire internet!
    destination_address_prefix = "*"
    description                = ""               # BAD: No description
  }

  # 🔴 BAD: RDP explicitly open (CIS 6.2)
  security_rule {
    name                       = "allow-rdp"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"            # 🔴 RDP from internet!
    source_address_prefix      = "*"               # 🔴
    destination_address_prefix = "*"
  }

  # 🔴 BAD: SSH open to internet (CIS 6.1)
  security_rule {
    name                       = "allow-ssh"
    priority                   = 300
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"              # 🔴 SSH from internet!
    source_address_prefix      = "*"               # 🔴
    destination_address_prefix = "*"
  }
}


# =============================================================================
# 🔴 STORAGE ACCOUNT – No HTTPS, Public Blobs, TLS 1.0, No Soft Delete
# CIS 3.1 – Ensure that storage account blocks public access
# CIS 3.7 – Ensure HTTPS traffic only
# CIS 3.15 – Ensure minimum TLS version 1.2
# =============================================================================
resource "azurerm_storage_account" "tigergate" {
  name                     = "tigergatestg2024"       # BAD: Predictable name
  resource_group_name      = azurerm_resource_group.tigergate.name
  location                 = azurerm_resource_group.tigergate.location
  account_tier             = "Standard"
  account_replication_type = "LRS"                    # BAD: No geo-redundancy

  enable_https_traffic_only       = false             # 🔴 CIS 3.7: HTTP allowed!
  allow_nested_items_to_be_public = true              # 🔴 CIS 3.1: Public blobs!
  shared_access_key_enabled       = true              # BAD: Key-based access allowed
  min_tls_version                 = "TLS1_0"          # 🔴 CIS 3.15: TLS 1.0 is broken!

  network_rules {
    default_action = "Allow"                          # 🔴 Allow all IPs
  }

  blob_properties {
    versioning_enabled = false                        # BAD: No version history
    delete_retention_policy { days = 0 }              # 🔴 Soft delete disabled
  }
}

# 🔴 BAD: Public blob container — world readable
resource "azurerm_storage_container" "public_data" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.tigergate.name
  container_access_type = "blob"                      # 🔴 Public read without auth!
}

# 🔴 BAD: Database backup container also public!
resource "azurerm_storage_container" "db_backups" {
  name                  = "database-backups"
  storage_account_name  = azurerm_storage_account.tigergate.name
  container_access_type = "container"                 # 🔴 Public list + read of backups!
}


# =============================================================================
# 🔴 AZURE SQL – No Auditing, No AD Auth, No Threat Detection
# CIS 4.1 – Ensure that 'Auditing' is set to 'On'
# CIS 4.2 – Ensure that AD authentication is used
# =============================================================================
resource "azurerm_mssql_server" "tigergate" {
  name                         = "tigergate-sql-server"
  resource_group_name          = azurerm_resource_group.tigergate.name
  location                     = azurerm_resource_group.tigergate.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "TigergateSQL123!"   # 🔴 Hardcoded password!
  # BAD: No Azure AD admin configured (CIS 4.2)
  # BAD: Minimum TLS not enforced at server level
  minimum_tls_version          = "Disabled"           # 🔴 TLS not required!
}

resource "azurerm_mssql_database" "tigergate" {
  name           = "tigergate-db"
  server_id      = azurerm_mssql_server.tigergate.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  # BAD: No transparent data encryption
  transparent_data_encryption_enabled = false         # 🔴 CIS 4.5: No encryption!
}

# BAD: Firewall rule allows ALL Azure + ALL internet access
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.tigergate.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"               # 🔴 ENTIRE internet!
}


# =============================================================================
# 🔴 AZURE KEY VAULT – Soft Delete Disabled, No Purge Protection
# CIS 8.5 – Ensure soft delete is enabled on Key Vaults
# =============================================================================
resource "azurerm_key_vault" "tigergate" {
  name                = "tigergate-kv"
  location            = azurerm_resource_group.tigergate.location
  resource_group_name = azurerm_resource_group.tigergate.name
  tenant_id           = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
  sku_name            = "standard"

  soft_delete_retention_days = 7                     # BAD: Minimum retention
  purge_protection_enabled   = false                  # 🔴 CIS 8.5: No purge protection!
  # BAD: No access policy restricting who can read secrets
}

output "storage_connection_string" {
  value     = azurerm_storage_account.tigergate.primary_connection_string
  sensitive = false  # 🔴 Connection string (contains key) NOT marked sensitive!
}
output "sql_admin_password" {
  value     = azurerm_mssql_server.tigergate.administrator_login_password
  sensitive = false  # 🔴 Password exposed in terraform output!
}
