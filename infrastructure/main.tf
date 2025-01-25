# Application Insights

resource "azurerm_application_insights" "example" {
  name                = "genai-insights-dev-cc-01"
  location            = var.location
  resource_group_name = var.resource_group_name
  application_type    = "web"
}

# Virtual Network

