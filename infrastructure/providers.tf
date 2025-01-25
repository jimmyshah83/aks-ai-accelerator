terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.7.0"
    }
  }
backend "azurerm" {
  resource_group_name  = "rg-genai-accelerator-dev-cc-iac-01"
  storage_account_name = "genaiacceleratordevcciac01"
  container_name       = "tfstate"
  key                  = "terraform.tfstate"
  use_oidc             = true
}
}
provider "azurerm" {
  features {}
  use_oidc = true
} 