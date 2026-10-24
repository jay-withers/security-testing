variable "administrator_object_id" {
  description = "Entra object ID of the administrator granted Key Vault Secrets Officer (to set the secrets) and Storage Blob Data Reader on the reports container. Explicit rather than taken from whoever runs `terraform apply`, because cd-terraform applies as the pipeline identity."
  type        = string
}

variable "environment" {
  description = "Deployment environment. Drives resource naming, and selects which shared platform environment this project deploys onto."
  type        = string

  validation {
    condition     = contains(["dev", "stg", "prd"], var.environment)
    error_message = "environment must be one of: dev, stg, prd."
  }
}
