# AWS Outputs
output "aws_vpc_id" {
  description = "AWS VPC ID"
  value       = module.aws_network.vpc_id
}

output "aws_cluster_endpoint" {
  description = "AWS EKS cluster endpoint"
  value       = module.aws_eks.cluster_endpoint
  sensitive   = true
}

output "aws_cluster_name" {
  description = "AWS EKS cluster name"
  value       = module.aws_eks.cluster_name
}

output "aws_rds_endpoint" {
  description = "AWS RDS PostgreSQL endpoint"
  value       = module.aws_database.db_instance_endpoint
}

output "aws_redis_endpoint" {
  description = "AWS ElastiCache Redis endpoint"
  value       = module.aws_cache.redis_endpoint
}

# Google Cloud Outputs
output "gcp_cluster_endpoint" {
  description = "GCP GKE cluster endpoint"
  value       = module.gcp_gke.cluster_endpoint
  sensitive   = true
}

output "gcp_cluster_name" {
  description = "GCP GKE cluster name"
  value       = module.gcp_gke.cluster_name
}

output "gcp_postgres_instance_connection_name" {
  description = "GCP Cloud SQL PostgreSQL connection name"
  value       = module.gcp_database.instance_connection_name
}

output "gcp_redis_instance_host" {
  description = "GCP Memorystore Redis host"
  value       = module.gcp_cache.redis_instance_host
}

# Azure Outputs
output "azure_cluster_endpoint" {
  description = "Azure AKS cluster endpoint"
  value       = module.azure_aks.cluster_endpoint
  sensitive   = true
}

output "azure_cluster_name" {
  description = "Azure AKS cluster name"
  value       = module.azure_aks.cluster_name
}

output "azure_postgres_server_fqdn" {
  description = "Azure Database for PostgreSQL server FQDN"
  value       = module.azure_database.server_fqdn
}

output "azure_redis_hostname" {
  description = "Azure Cache for Redis hostname"
  value       = module.azure_cache.redis_hostname
}

# Common Outputs
output "api_gateway_url" {
  description = "API Gateway URL"
  value       = "https://api.${var.domain_name}"
}

output "soc_dashboard_url" {
  description = "SOC Dashboard URL"
  value       = "https://soc.${var.domain_name}"
}

output "grafana_url" {
  description = "Grafana monitoring URL"
  value       = "https://grafana.${var.domain_name}"
}

output "kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${local.name_prefix}-cluster"
}

# Security Outputs
output "security_group_ids" {
  description = "Security group IDs for reference"
  value = {
    aws     = module.aws_security.security_group_ids
    gcp     = module.gcp_security.firewall_rules
    azure   = module.azure_security.security_group_ids
  }
  sensitive = true
}