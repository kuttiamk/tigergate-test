provider "azurerm" {
  features {}
}
resource "azurerm_network_security_group" "open_nsg" {
  name                = "open-nsg"
  location            = "East US"
  resource_group_name = "tigergate-rg"

  security_rule {
    name                       = "allow_all_inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*" # CSPM alert
    destination_address_prefix = "*"
  }
}
