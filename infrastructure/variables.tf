variable "location" {
  description = "The location where the resource will be created"
  type        = string
  default     = "Canada Central"
}

variable "resource_group_name" {
  description = "The name of the resource group"
  type        = string
  default     = "rg-genai-accelerator-dev-cc-iac-01"
}