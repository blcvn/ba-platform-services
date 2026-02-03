# 🚀 Auth Service - Quick Reference

## Environment Variables

```bash
# Required Config Files
CONFIG_FILE=./config/config.yaml              # Non-sensitive settings
SECRET_FILE=/tmp/auth-service-secrets.json    # Sensitive data (DB, Redis, JWT)

# Service Settings
SERVICE_NAME=auth-service
JAEGER_URL=localhost:4317
GRPC_PORT=9090
HTTP_PORT=8080
METRICS_PATH=/metrics
```

## Quick Commands

### Local Development
```bash
# First time setup
./setup-local.sh

# Run
make run

# Run with custom config
make run CONFIG_FILE=./config/config.local.yaml SECRET_FILE=/tmp/secrets.json

# Build binary
make build

# Run tests
make test
```

### Docker
```bash
# Build image
make docker-build

# Run container
make docker-run

# View logs
make docker-logs

# Stop container
make docker-stop
```

### Docker Compose
```bash
cd deployment/docker
docker-compose up -d auth-service
docker-compose logs -f auth-service
docker-compose down
```

## File Locations

### Development
```
services/auth-service/
├── config/
│   ├── config.yaml              ← Main config (commit this)
│   ├── config.local.yaml        ← Local dev (gitignored)
│   └── secrets.example.json     ← Template (commit this)
└── /tmp/auth-service-secrets.json  ← Actual secrets (gitignored)
```

### Docker Container
```
/app/
├── config/
│   └── config.yaml              ← Mounted or copied
/vault/
└── secrets/
    └── config.json              ← Mounted from Vault Agent
/bin/
└── auth-service                 ← Binary
```

## Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| gRPC | `localhost:9090` | gRPC services |
| HTTP | `localhost:8080` | REST API (grpc-gateway) |
| Metrics | `http://localhost:8080/metrics` | Prometheus metrics |

## Config Files Format

### config.yaml (Non-sensitive)
```yaml
kong_headers:
  user_id_header: "X-User-ID"
  tenant_id_header: "X-Tenant-ID"
  roles_header: "X-Roles"

roles:
  super_admin_role: "super-admin"

mtls:
  cert_path: "/vault/secrets/bundle.pem"
  key_path: "/vault/secrets/bundle.pem"
```

### secrets.json (Sensitive)
```json
{
  "database": {
    "url": "postgresql://user:pass@host:5432/dbname?sslmode=disable"
  },
  "redis": {
    "addr": "localhost:6379",
    "password": "",
    "db": 0
  },
  "jwt_secret": "your-secret-min-32-chars"
}
```

## Troubleshooting

### "failed to open config"
```bash
# Check file exists
ls -la $CONFIG_FILE

# Use absolute path
export CONFIG_FILE=$(pwd)/config/config.yaml
```

### "DATABASE_URL is not set"
```bash
# Check secrets file
cat $SECRET_FILE | jq .

# Or set directly
export DATABASE_URL="postgresql://..."
```

### Docker volume issues
```bash
# Use absolute paths
make docker-run SECRET_FILE=$(pwd)/config/secrets.json
```

## Common Scenarios

### Scenario 1: Local Dev with PostgreSQL & Redis
```bash
# Start dependencies
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres --name postgres postgres
docker run -d -p 6379:6379 --name redis redis

# Setup
./setup-local.sh

# Run
make run
```

### Scenario 2: Custom Ports
```bash
make run GRPC_PORT=9091 HTTP_PORT=8081
```

### Scenario 3: Different Config
```bash
make run \
  CONFIG_FILE=./config/config.production.yaml \
  SECRET_FILE=/secure/secrets.json
```

### Scenario 4: Docker with Local Secrets
```bash
# Create secrets file
cat > /tmp/secrets.json << EOF
{
  "database": {"url": "postgresql://..."},
  "redis": {"addr": "host.docker.internal:6379", "password": "", "db": 0},
  "jwt_secret": "local-dev-secret-key-min-32-chars"
}
EOF

# Run
make docker-run SECRET_FILE=/tmp/secrets.json
```

## Documentation

- 📖 [BUILD_AND_RUN.md](./BUILD_AND_RUN.md) - Complete build & run guide
- 📖 [CONFIG_GUIDE.md](./config/CONFIG_GUIDE.md) - Configuration details
- 📖 [ENVIRONMENT_VARIABLES.md](./ENVIRONMENT_VARIABLES.md) - All env vars
- 📖 [CHANGELOG_ENV_VARS.md](./CHANGELOG_ENV_VARS.md) - Recent changes

## Support

Need help? Check:
1. Documentation files above
2. Example files in `config/`
3. Error messages in logs: `make docker-logs`
