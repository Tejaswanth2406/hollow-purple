terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    bucket = "hollow-purple-terraform-state"
    key    = "infrastructure/terraform.tfstate"
    region = "us-east-1"
  }
}

# AWS Provider
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "Hollow Purple"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Google Cloud Provider
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Azure Provider
provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

# Kubernetes Provider (will be configured per cluster)
provider "kubernetes" {
  # Configuration will be set based on the target cluster
}

# Helm Provider
provider "helm" {
  kubernetes {
    # Configuration will be set based on the target cluster
  }
}

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "gcp_project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "azure_subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

# Local values
locals {
  name_prefix = "hollow-purple-${var.environment}"
  common_tags = {
    Project     = "Hollow Purple"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}