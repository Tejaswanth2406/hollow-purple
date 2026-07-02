# Hollow Purple Secrets Directory

This directory is intentionally empty in the repository and is used to store
sensitive configuration files and secrets that should not be committed to version control.

## Usage

Place the following files here (create them manually or via scripts):

### Database Secrets
- `postgres-password.txt` - PostgreSQL database password
- `redis-password.txt` - Redis password
- `neo4j-password.txt` - Neo4j database password

### API Keys
- `openai-api-key.txt` - OpenAI API key for AI reasoning
- `jwt-secret.txt` - JWT signing secret
- `encryption-key.txt` - AES encryption key

### Cloud Credentials
- `aws-credentials.env` - AWS access keys
- `gcp-service-account.json` - GCP service account key
- `azure-credentials.env` - Azure service principal credentials

## Security Notes

- Never commit actual secrets to this directory
- Use environment-specific secret management (AWS Secrets Manager, GCP Secret Manager, etc.)
- Rotate secrets regularly
- Use strong, randomly generated secrets
- Audit access to secrets

## Bootstrap Script

Use `scripts/bootstrap_env.py` to initialize secrets for development.