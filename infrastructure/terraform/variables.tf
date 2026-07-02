# Environment Configuration
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod"
  }
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "aws_vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aws_availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# Google Cloud Configuration
variable "gcp_project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "Google Cloud zone"
  type        = string
  default     = "us-central1-a"
}

# Azure Configuration
variable "azure_subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "East US"
}

variable "azure_resource_group_name" {
  description = "Azure Resource Group name"
  type        = string
  default     = "hollow-purple-rg"
}

# Cluster Configuration
variable "cluster_name" {
  description = "Kubernetes cluster name"
  type        = string
  default     = "hollow-purple-cluster"
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.27.0"
}

variable "node_instance_type" {
  description = "Instance type for worker nodes"
  type        = string
  default     = "t3.large"
}

variable "min_node_count" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 3
}

variable "max_node_count" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 20
}

variable "desired_node_count" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 5
}

# Database Configuration
variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "15"
}

variable "postgres_instance_class" {
  description = "PostgreSQL instance class"
  type        = string
  default     = "db.t3.large"
}

variable "redis_node_type" {
  description = "Redis node type"
  type        = string
  default     = "cache.t3.medium"
}

# Security Configuration
variable "enable_deletion_protection" {
  description = "Enable deletion protection for resources"
  type        = bool
  default     = true
}

variable "allowed_ip_ranges" {
  description = "List of allowed IP ranges for access"
  type        = list(string)
  default     = []
}

# Monitoring Configuration
variable "enable_monitoring" {
  description = "Enable monitoring stack (Prometheus/Grafana)"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable centralized logging"
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "Log retention in days"
  type        = number
  default     = 30
}

# Domain Configuration
variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "hollow-purple.com"
}

variable "create_route53_zone" {
  description = "Create Route53 hosted zone"
  type        = bool
  default     = false
}