# Environment Variables Configuration Summary

## Overview
Auth-service sử dụng hai loại configuration files và có thể override bằng environment variables.

## Environment Variables

### Configuration File Paths
| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `config.yaml` | Path to YAML config file (non-sensitive settings) |
| `SECRET_FILE` | `/vault/secrets/config.json` | Path to JSON secrets file (sensitive data) |

### Service Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `SERVICE_NAME` | `auth-service` | Name of the service |
| `JAEGER_URL` | `localhost:4317` | Jaeger OTLP endpoint for tracing |
| `METRICS_PATH` | `/metrics` | Prometheus metrics endpoint path |
| `GRPC_PORT` | `9090` | gRPC server port |
| `HTTP_PORT` | `8080` | HTTP/REST server port |

### Kong Headers (from config.yaml or env vars)
| Variable | Default | Description |
|----------|---------|-------------|
| `KONG_HEADER_USER_ID` | `X-User-ID` | Header name for user ID |
| `KONG_HEADER_TENANT_ID` | `X-Tenant-ID` | Header name for tenant ID |
| `KONG_HEADER_ROLES` | `X-Roles` | Header name for user roles |

### Role Configuration (from config.yaml or env vars)
| Variable | Default | Description |
|----------|---------|-------------|
| `SUPER_ADMIN_ROLE` | `super-admin` | Name of super admin role |

### Secrets (from SECRET_FILE or env vars as fallback)
| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_ADDR` | Yes | Redis server address (host:port) |
| `JWT_SECRET` | Yes | JWT signing secret (min 32 chars) |

## Configuration Priority

Thứ tự ưu tiên từ cao đến thấp:

1. **Environment Variables** - Cao nhất
2. **Secrets File** (`SECRET_FILE`) - Cho sensitive data
3. **Config File** (`CONFIG_FILE`) - Cho non-sensitive settings
4. **Default Values** - Hardcoded trong code

## Usage Examples

### Local Development với Makefile

```bash
# Sử dụng default values
make run

# Override config và secret files
make run CONFIG_FILE=./config/config.local.yaml SECRET_FILE=/tmp/secrets.json

# Override specific ports
make run GRPC_PORT=9091 HTTP_PORT=8081

# Override tất cả
make run \
  CONFIG_FILE=./config/config.local.yaml \
  SECRET_FILE=/tmp/secrets.json \
  SERVICE_NAME=my-auth \
  GRPC_PORT=9091 \
  HTTP_PORT=8081 \
  JAEGER_URL=localhost:4317
```

### Docker Run

```bash
# Build image
make docker-build

# Run với default settings
make docker-run

# Run với custom config
make docker-run \
  CONFIG_FILE=./config/config.yaml \
  SECRET_FILE=/tmp/auth-service-secrets.json \
  GRPC_PORT=9091 \
  HTTP_PORT=8081
```

### Docker Compose

File `docker-compose.yml` đã được cấu hình với:

```yaml
environment:
  SERVICE_NAME: auth-service
  JAEGER_URL: jaeger:4317
  METRICS_PATH: /metrics
  GRPC_PORT: 9090
  HTTP_PORT: 8080
  CONFIG_FILE: /app/config/config.yaml
  SECRET_FILE: /vault/secrets/config.json
volumes:
  - auth-service-secrets:/vault/secrets:ro
  - ../../services/auth-service/config/config.yaml:/app/config/config.yaml:ro
```

### Direct Binary Execution

```bash
# Export environment variables
export CONFIG_FILE=./config/config.yaml
export SECRET_FILE=/tmp/auth-service-secrets.json

# Run
./bin/auth-service gateway \
  --service-name=auth-service \
  --jaeger-url=localhost:4317 \
  --metrics-path=/metrics \
  --grpc-port=9090 \
  --http-port=8080
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        env:
        - name: SERVICE_NAME
          value: "auth-service"
        - name: JAEGER_URL
          value: "jaeger-collector:4317"
        - name: CONFIG_FILE
          value: "/app/config/config.yaml"
        - name: SECRET_FILE
          value: "/vault/secrets/config.json"
        # Secrets từ Vault hoặc K8s Secrets
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-service-secrets
              key: database-url
        - name: REDIS_ADDR
          valueFrom:
            secretKeyRef:
              name: auth-service-secrets
              key: redis-addr
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-service-secrets
              key: jwt-secret
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: vault-secrets
          mountPath: /vault/secrets
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: auth-service-config
      - name: vault-secrets
        # Vault Agent sidecar sẽ write vào đây
        emptyDir: {}
```

## File Locations

### Development
- Config: `./config/config.yaml` hoặc `./config/config.local.yaml`
- Secrets: `/tmp/auth-service-secrets.json` (default trong Makefile)

### Docker
- Config: `/app/config/config.yaml` (mounted từ host hoặc copied trong image)
- Secrets: `/vault/secrets/config.json` (mounted từ Vault Agent)

### Production (Kubernetes)
- Config: `/app/config/config.yaml` (từ ConfigMap)
- Secrets: `/vault/secrets/config.json` (từ Vault Agent sidecar)

## Troubleshooting

### Error: "failed to open config"
```bash
# Check CONFIG_FILE path
echo $CONFIG_FILE

# Verify file exists
ls -la $CONFIG_FILE

# Check permissions
stat $CONFIG_FILE
```

### Error: "DATABASE_URL is not set"
```bash
# Check SECRET_FILE exists
ls -la $SECRET_FILE

# Check JSON format
cat $SECRET_FILE | jq .

# Or set via environment variable
export DATABASE_URL="postgresql://user:pass@localhost:5432/dbname"
```

### Docker volume mount issues
```bash
# Ensure files exist before mounting
ls -la ./config/config.yaml
ls -la /tmp/auth-service-secrets.json

# Use absolute paths
make docker-run SECRET_FILE=$(pwd)/config/secrets.json
```

## Best Practices

### ✅ DO:
- Sử dụng `CONFIG_FILE` cho non-sensitive settings
- Sử dụng `SECRET_FILE` hoặc env vars cho sensitive data
- Mount config files read-only trong Docker/K8s
- Sử dụng Vault Agent trong production
- Set proper file permissions (600 cho secrets)

### ❌ DON'T:
- Commit secrets vào Git
- Hardcode sensitive values trong config.yaml
- Share secrets giữa các environments
- Mount secrets writable trong containers
- Sử dụng example secrets trong production
