# Auth Service Configuration Guide

## Configuration Files

The auth-service uses a two-tier configuration system:

### 1. **config.yaml** - Non-sensitive Configuration
Contains non-sensitive settings like header names, role names, and file paths.

**Location:** `./config/config.yaml`

**Can be overridden by:** `CONFIG_FILE` environment variable

### 2. **Vault Secrets** - Sensitive Configuration
Contains sensitive data like database credentials, Redis passwords, and JWT secrets.

**Default Location:** `/vault/secrets/config.json`

**Can be overridden by:** `SECRET_FILE` environment variable

## Configuration Structure

### config.yaml
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

### Vault Secrets (JSON)
```json
{
  "database": {
    "url": "postgresql://user:pass@host:5432/dbname",
    "username": "user",
    "password": "password"
  },
  "redis": {
    "addr": "localhost:6379",
    "password": "",
    "db": 0
  },
  "jwt_secret": "your-secret-key-min-32-characters"
}
```

## Environment Variable Overrides

All configuration values can be overridden by environment variables:

### Kong Headers
- `KONG_HEADER_USER_ID` - Override user ID header name
- `KONG_HEADER_TENANT_ID` - Override tenant ID header name
- `KONG_HEADER_ROLES` - Override roles header name

### Roles
- `SUPER_ADMIN_ROLE` - Override super admin role name

### Secrets (Fallback)
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_ADDR` - Redis server address
- `JWT_SECRET` - JWT signing secret

### File Paths
- `CONFIG_FILE` - Path to config.yaml (default: `config.yaml`)
- `SECRET_FILE` - Path to secrets JSON (default: `/vault/secrets/config.json`)

## Local Development Setup

### Option 1: Using Local Files

1. **Copy the example files:**
   ```bash
   cp config/config.local.yaml config/config.yaml
   cp config/secrets.example.json /tmp/secrets.json
   ```

2. **Update secrets.json with your local values:**
   ```bash
   vim /tmp/secrets.json
   ```

3. **Run with environment variables:**
   ```bash
   export SECRET_FILE=/tmp/secrets.json
   make run
   ```

### Option 2: Using Environment Variables Only

```bash
export DATABASE_URL="postgresql://user:pass@localhost:5432/auth_db?sslmode=disable"
export REDIS_ADDR="localhost:6379"
export JWT_SECRET="your-local-development-secret-key-min-32-chars"

make run
```

### Option 3: Using Docker Compose

Create a `.env` file:
```env
DATABASE_URL=postgresql://auth_user:auth_password@postgres:5432/auth_db?sslmode=disable
REDIS_ADDR=redis:6379
JWT_SECRET=local-dev-secret-key-change-in-production-min-32-characters
```

## Production Setup

### Using Vault Agent

1. **Configure Vault Agent** to write secrets to `/vault/secrets/config.json`

2. **Mount certificates** to `/vault/secrets/bundle.pem`

3. **Deploy config.yaml** as a ConfigMap in Kubernetes:
   ```bash
   kubectl create configmap auth-service-config \
     --from-file=config.yaml=config/config.yaml
   ```

4. **Mount the ConfigMap** in your deployment:
   ```yaml
   volumeMounts:
     - name: config
       mountPath: /app/config
   volumes:
     - name: config
       configMap:
         name: auth-service-config
   ```

### Using Kubernetes Secrets (Alternative)

If not using Vault, you can use Kubernetes secrets:

```bash
kubectl create secret generic auth-service-secrets \
  --from-literal=database-url='postgresql://...' \
  --from-literal=redis-addr='redis:6379' \
  --from-literal=jwt-secret='your-production-secret'
```

Then set environment variables in your deployment:
```yaml
env:
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
```

## Configuration Priority

The configuration is loaded in the following order (highest priority first):

1. **Environment Variables** - Highest priority
2. **Vault Secrets JSON** - For sensitive data
3. **config.yaml** - For non-sensitive settings
4. **Default Values** - Hardcoded in constants.go

## Security Best Practices

### ✅ DO:
- Store sensitive data in Vault or Kubernetes Secrets
- Use strong, randomly generated JWT secrets (min 32 characters)
- Use SSL/TLS for database connections in production
- Rotate JWT secrets regularly
- Use different secrets for each environment

### ❌ DON'T:
- Commit secrets to version control
- Use the example secrets in production
- Share secrets between environments
- Use weak or predictable JWT secrets
- Disable SSL for database connections in production

## Troubleshooting

### "failed to open config" error
- Check that `SECRET_FILE` path is correct
- Ensure Vault Agent has written the secrets file
- Verify file permissions (should be readable by the app user)

### "DATABASE_URL is not set" error
- Check Vault secrets contain `database.url`
- Or set `DATABASE_URL` environment variable
- Verify JSON format in secrets file

### "failed to load mTLS certificates" warning
- Check `mtls.cert_path` and `mtls.key_path` in config.yaml
- Verify certificate files exist and are readable
- For local dev without TLS, this warning can be ignored

## Example Configurations

### Minimal Local Development
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
export REDIS_ADDR="localhost:6379"
export JWT_SECRET="local-development-secret-key-minimum-32-characters-required"
go run main.go gateway
```

### Production with Vault
```bash
# Vault Agent writes to /vault/secrets/config.json
# ConfigMap mounted at /app/config/config.yaml
./auth-service gateway \
  --service-name=auth-service \
  --jaeger-url=jaeger-collector:4317 \
  --grpc-port=9090 \
  --http-port=8080
```
