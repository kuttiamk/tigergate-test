data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "owner_assignment" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Owner" # CIEM alert
  principal_id         = "11111111-1111-1111-1111-111111111111"
}
