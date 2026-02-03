# Auth Service

Enterprise-grade authentication service với gRPC và HTTP/REST API support, được xây dựng với Go và Kratos framework.

## 🌟 Features

- ✅ **Dual Protocol Support**: gRPC và HTTP/REST (via grpc-gateway)
- ✅ **JWT Authentication**: Access tokens với JWT, refresh tokens với opaque tokens
- ✅ **Session Management**: Persistent sessions trong PostgreSQL
- ✅ **Token Rotation**: Mandatory refresh token rotation
- ✅ **Token Revocation**: Blacklist support với Redis
- ✅ **Multi-tenancy**: Tenant isolation support
- ✅ **Role-based Access Control**: User roles và permissions
- ✅ **Audit Logging**: Complete audit trail cho authentication events
- ✅ **Observability**: Distributed tracing (Jaeger), metrics (Prometheus)
- ✅ **Security**: mTLS support, non-root containers, secret management với Vault

## 🚀 Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Redis 7+
- Docker (optional)

### Local Development

```bash
# 1. Setup (first time only)
./setup-local.sh

# 2. Start dependencies
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres --name postgres postgres
docker run -d -p 6379:6379 --name redis redis

# 3. Run the service
make run
```

Service sẽ chạy trên:
- gRPC: `localhost:9090`
- HTTP: `localhost:8080`
- Metrics: `http://localhost:8080/metrics`

### Docker

```bash
# Build và run
make docker-build
make docker-run

# View logs
make docker-logs

# Stop
make docker-stop
```

### Docker Compose

```bash
cd ../../deployment/docker
docker-compose up -d auth-service
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) | Quick commands và common scenarios |
| [BUILD_AND_RUN.md](./BUILD_AND_RUN.md) | Complete build & deployment guide |
| [ENVIRONMENT_VARIABLES.md](./ENVIRONMENT_VARIABLES.md) | All environment variables reference |
| [config/CONFIG_GUIDE.md](./config/CONFIG_GUIDE.md) | Configuration guide chi tiết |
| [CHANGELOG_ENV_VARS.md](./CHANGELOG_ENV_VARS.md) | Recent configuration changes |

## 🔧 Configuration

Auth service sử dụng hai configuration files:

### 1. config.yaml (Non-sensitive)
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

### 2. secrets.json (Sensitive - from Vault)
```json
{
  "database": {
    "url": "postgresql://user:pass@host:5432/dbname"
  },
  "redis": {
    "addr": "localhost:6379",
    "password": "",
    "db": 0
  },
  "jwt_secret": "your-secret-min-32-chars"
}
```

### Environment Variables

```bash
CONFIG_FILE=./config/config.yaml              # Config file path
SECRET_FILE=/vault/secrets/config.json        # Secrets file path
SERVICE_NAME=auth-service                     # Service name
JAEGER_URL=localhost:4317                     # Jaeger endpoint
GRPC_PORT=9090                                # gRPC port
HTTP_PORT=8080                                # HTTP port
```

Xem [ENVIRONMENT_VARIABLES.md](./ENVIRONMENT_VARIABLES.md) để biết đầy đủ danh sách.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Auth Service                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │  gRPC Server │         │  HTTP Server │                  │
│  │   (Port 9090)│         │  (Port 8080) │                  │
│  └──────┬───────┘         └──────┬───────┘                  │
│         │                        │                           │
│         └────────┬───────────────┘                           │
│                  │                                            │
│         ┌────────▼────────┐                                  │
│         │   Controllers   │                                  │
│         │  - Authen       │                                  │
│         │  - User Role    │                                  │
│         └────────┬────────┘                                  │
│                  │                                            │
│         ┌────────▼────────┐                                  │
│         │    Use Cases    │                                  │
│         │  - Auth UC      │                                  │
│         │  - Role UC      │                                  │
│         └────────┬────────┘                                  │
│                  │                                            │
│    ┌─────────────┼─────────────┐                            │
│    │             │             │                             │
│ ┌──▼──────┐  ┌──▼──────┐  ┌──▼──────┐                      │
│ │  Repos  │  │ Helpers │  │ Entities│                       │
│ │- User   │  │- Hash   │  │- Models │                       │
│ │- Session│  │- Utils  │  │- DTOs   │                       │
│ │- Role   │  │- Valid  │  └─────────┘                       │
│ │- Audit  │  │- Trans  │                                     │
│ └────┬────┘  └─────────┘                                     │
│      │                                                        │
│ ┌────▼────────────────┐                                      │
│ │   PostgreSQL        │                                      │
│ │   Redis             │                                      │
│ └─────────────────────┘                                      │
└─────────────────────────────────────────────────────────────┘
```

## 🔌 API Endpoints

### gRPC Services

- `AuthenticateService`
  - `Register` - User registration
  - `Login` - User login
  - `Logout` - User logout
  - `RefreshToken` - Refresh access token
  - `RevokeToken` - Revoke token
  - `VerifyToken` - Verify token validity

- `UserRoleService`
  - `ActiveUser` - Activate user
  - `InactiveUser` - Deactivate user
  - (More role management endpoints)

### HTTP/REST (grpc-gateway)

Tất cả gRPC endpoints đều available qua HTTP/REST tại `http://localhost:8080`

### Metrics

- `GET /metrics` - Prometheus metrics

## 🧪 Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Generate mocks
make mock
```

## 🔨 Development

### Project Structure

```
auth-service/
├── cmd/                    # Commands
│   ├── cmd.go             # Root command
│   └── gateway.go         # Gateway implementation
├── common/
│   └── configs/           # Configuration management
├── config/                # Config files
│   ├── config.yaml        # Main config
│   └── *.example.*        # Example files
├── controllers/           # API controllers
├── dto/                   # Data transfer objects
├── entities/              # Domain entities
├── helper/                # Helper utilities
├── repository/            # Data repositories
│   ├── postgres/          # PostgreSQL repos
│   └── redis/             # Redis repos
├── usecases/              # Business logic
├── main.go               # Entry point
├── Dockerfile            # Container image
└── Makefile              # Build automation
```

### Adding New Features

1. Define protobuf messages và services
2. Generate Go code: `make proto`
3. Implement repository layer
4. Implement use case layer
5. Implement controller layer
6. Add tests
7. Update documentation

### Code Style

```bash
# Format code
make fmt

# Run linter
make lint

# Run vet
make vet
```

## 🚢 Deployment

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 9090
          name: grpc
        - containerPort: 8080
          name: http
        env:
        - name: CONFIG_FILE
          value: /app/config/config.yaml
        - name: SECRET_FILE
          value: /vault/secrets/config.json
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: vault-secrets
          mountPath: /vault/secrets
      volumes:
      - name: config
        configMap:
          name: auth-service-config
```

### Vault Integration

Service tự động load secrets từ Vault Agent:
- Secrets file: `/vault/secrets/config.json`
- TLS certificates: `/vault/secrets/bundle.pem`

## 📊 Monitoring

### Metrics

Service expose Prometheus metrics tại `/metrics`:
- Request counts
- Request durations
- Error rates
- Custom business metrics

### Tracing

Distributed tracing với Jaeger:
- Automatic span creation
- Request tracing across services
- Performance analysis

### Logging

Structured logging với levels:
- `INFO` - Normal operations
- `WARN` - Warnings
- `ERROR` - Errors
- `FATAL` - Fatal errors

## 🔒 Security

- **mTLS**: Mutual TLS cho service-to-service communication
- **JWT**: Secure token-based authentication
- **Token Rotation**: Mandatory refresh token rotation
- **Token Revocation**: Redis-based token blacklist
- **Audit Logging**: Complete audit trail
- **Non-root Container**: Runs as non-root user (UID 1000)
- **Secret Management**: Vault integration
- **Input Validation**: Request validation
- **SQL Injection Prevention**: Parameterized queries

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Run tests và linters
6. Submit pull request

## 📝 License

[Your License Here]

## 🆘 Support

- Documentation: Xem các file trong thư mục này
- Issues: [GitHub Issues]
- Contact: [Your Contact]

## 🎯 Roadmap

- [ ] OAuth2/OIDC support
- [ ] MFA (Multi-factor authentication)
- [ ] Password reset flow
- [ ] Email verification
- [ ] Social login (Google, GitHub, etc.)
- [ ] API rate limiting
- [ ] GraphQL API
- [ ] WebSocket support
