# Hollow Purple Infrastructure

This directory contains the complete infrastructure setup for deploying Hollow Purple across multiple cloud platforms with enterprise-grade security, monitoring, and scalability.

## Architecture Overview

Hollow Purple is deployed using a microservices architecture with clear separation between Control Plane (AI reasoning, autonomous decisions) and Data Plane (real-time processing, ingestion). The infrastructure supports multi-cloud deployment with automated CI/CD pipelines.

### Components

- **API Gateway**: FastAPI-based REST/WebSocket interface with authentication
- **Control Plane**: AI reasoning, Mahoraga decision engine, policy enforcement
- **Data Plane**: Real-time ingestion, processing, anomaly detection
- **Deception Engine**: Safe attacker redirection and intelligence gathering
- **Databases**: PostgreSQL (events), Neo4j (graphs), Redis (cache)
- **Message Queue**: Kafka for event streaming
- **Stream Processing**: Flink for real-time analytics
- **Monitoring**: Prometheus + Grafana for observability

## Quick Start

### Local Development

1. **Start services with Docker Compose:**
   ```bash
   cd infrastructure
   docker-compose up -d
   ```

2. **Access services:**
   - API Gateway: http://localhost:8000
   - SOC Dashboard: http://localhost:8080
   - Grafana: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9090

### Production Deployment

1. **Prerequisites:**
   - Kubernetes cluster (EKS/GKE/AKS)
   - Terraform >= 1.0
   - kubectl configured
   - Cloud provider CLI tools

2. **Deploy infrastructure:**
   ```bash
   cd infrastructure/terraform
   terraform init
   terraform plan -var-file=production.tfvars
   terraform apply -var-file=production.tfvars
   ```

3. **Deploy application:**
   ```bash
   kubectl apply -f ../k8s/
   kubectl rollout status deployment/hollow-purple-api
   ```

## Directory Structure

```
infrastructure/
├── Dockerfile              # Multi-stage production build
├── docker-compose.yml      # Local development environment
├── k8s/                    # Kubernetes manifests
│   ├── deployment.yaml     # Main application deployment
│   ├── service.yaml        # Services and ingress
│   ├── configmap.yaml      # Configuration data
│   ├── secret.yaml         # Sensitive configuration
│   ├── rbac.yaml          # Role-based access control
│   ├── network-policy.yaml # Network security policies
│   └── autoscaling.yaml    # HPA and PDB configurations
├── terraform/              # Infrastructure as Code
│   ├── main.tf            # Main Terraform configuration
│   ├── variables.tf       # Variable definitions
│   ├── outputs.tf         # Output definitions
│   └── modules/           # Reusable Terraform modules
├── monitoring/            # Observability stack
│   ├── prometheus.yml     # Prometheus configuration
│   ├── alert_rules.yml    # Alert definitions
│   └── grafana/           # Grafana dashboards
└── README.md              # This file
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| ENVIRONMENT | Runtime environment | development |
| REDIS_URL | Redis connection URL | redis://redis:6379 |
| POSTGRES_URL | PostgreSQL connection URL | Required |
| KAFKA_BOOTSTRAP_SERVERS | Kafka broker addresses | kafka:9092 |
| OPENAI_API_KEY | OpenAI API key | Required for AI features |

### Secrets Management

Sensitive data is managed through Kubernetes secrets:

```bash
# Create secrets from environment variables
kubectl create secret generic hollow-purple-secrets \
  --from-literal=redis-url=$REDIS_URL \
  --from-literal=postgres-url=$POSTGRES_URL \
  --from-literal=neo4j-uri=$NEO4J_URI \
  --from-literal=openai-api-key=$OPENAI_API_KEY \
  --from-literal=jwt-secret=$JWT_SECRET \
  --namespace hollow-purple
```

## Security

### Network Security

- **Network Policies**: Restrict pod-to-pod communication
- **RBAC**: Role-based access control for Kubernetes resources
- **TLS**: End-to-end encryption with cert-manager
- **Secrets**: Encrypted sensitive data storage

### Container Security

- **Non-root containers**: All containers run as non-root users
- **Read-only filesystems**: Immutable container filesystems
- **Security contexts**: Pod security standards enforcement
- **Image scanning**: Automated vulnerability scanning in CI/CD

### Authentication & Authorization

- **JWT tokens**: Stateless authentication
- **Role-based access**: SOC analyst, admin, read-only roles
- **API rate limiting**: Protection against abuse
- **Audit logging**: Comprehensive security event logging

## Monitoring & Observability

### Metrics Collection

- **Application metrics**: Custom business metrics
- **System metrics**: CPU, memory, disk, network
- **Security metrics**: Threats, attacks, deception events
- **Performance metrics**: Latency, throughput, error rates

### Alerting

Critical alerts are configured for:
- Service downtime
- High error rates
- Resource exhaustion
- Security incidents
- Performance degradation

### Dashboards

Pre-configured Grafana dashboards provide:
- System health overview
- Threat detection metrics
- Performance monitoring
- Security event analysis
- Resource utilization

## Scaling

### Horizontal Pod Autoscaling

Based on:
- CPU utilization (>70%)
- Memory utilization (>80%)
- Custom metrics (HTTP requests/sec)

### Cluster Autoscaling

- Node pool scaling based on resource demands
- Multi-zone deployment for high availability
- Cost optimization with spot instances

## Backup & Recovery

### Database Backups

- Automated PostgreSQL backups
- Point-in-time recovery capability
- Cross-region backup replication

### Disaster Recovery

- Multi-region deployment option
- Automated failover procedures
- Data replication strategies

## CI/CD Pipeline

### GitHub Actions Workflow

1. **Security scanning**: Code and dependency analysis
2. **Testing**: Unit and integration tests
3. **Building**: Multi-stage Docker image creation
4. **Infrastructure testing**: Terraform and Kubernetes validation
5. **Deployment**: Blue-green deployment strategy
6. **Monitoring**: Post-deployment health checks

### Deployment Strategy

- **Development**: Direct deployment to dev environment
- **Staging**: Full pipeline with integration tests
- **Production**: Blue-green deployment with canary analysis

## Troubleshooting

### Common Issues

1. **Pod crashes**: Check logs with `kubectl logs`
2. **Service unavailable**: Verify network policies and service discovery
3. **High resource usage**: Monitor with Grafana dashboards
4. **Failed deployments**: Check rollout status and events

### Debug Commands

```bash
# Check pod status
kubectl get pods -n hollow-purple

# View logs
kubectl logs -f deployment/hollow-purple-api -n hollow-purple

# Check events
kubectl get events -n hollow-purple --sort-by=.metadata.creationTimestamp

# Debug network issues
kubectl exec -it deployment/hollow-purple-api -n hollow-purple -- curl http://localhost:8000/health

# Check resource usage
kubectl top pods -n hollow-purple
```

## Contributing

1. Follow infrastructure as code best practices
2. Test changes in development environment first
3. Update documentation for configuration changes
4. Ensure security compliance for new components
5. Add monitoring for new services

## Support

For issues and questions:
- Check the troubleshooting section above
- Review monitoring dashboards for insights
- Check application logs for error details
- Create issues with relevant labels and context