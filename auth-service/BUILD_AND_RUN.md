# Auth Service - Build & Run Guide

## Quick Start

### Using Makefile

#### View all available commands
```bash
make help
```

#### Run locally (development)
```bash
# Run with default settings (gRPC:9090, HTTP:8080)
make run

# Run with custom ports
make run GRPC_PORT=9091 HTTP_PORT=8081

# Run with custom Jaeger endpoint
make run JAEGER_URL=jaeger.example.com:4317

# Run with all custom parameters
make run SERVICE_NAME=my-auth GRPC_PORT=9091 HTTP_PORT=8081 JAEGER_URL=localhost:4317
```

#### Build and run binary
```bash
# Build the binary
make build

# Run the built binary
make run-binary

# Or build and run in one command
make run-binary GRPC_PORT=9090 HTTP_PORT=8080
```

#### Testing
```bash
# Run tests
make test

# Run tests with coverage report
make test-coverage
```

#### Docker operations
```bash
# Build Docker image
make docker-build

# Run Docker container
make docker-run

# Run with custom ports
make docker-run GRPC_PORT=9091 HTTP_PORT=8081

# View logs
make docker-logs

# Stop and remove container
make docker-stop
```

#### Code quality
```bash
# Format code
make fmt

# Run linter
make lint

# Run go vet
make vet

# Run all checks and build
make all
```

### Using Docker

#### Build the image
```bash
docker build -t auth-service:latest -f services/auth-service/Dockerfile .
```

#### Run with default settings
```bash
docker run -d \
  --name auth-service \
  -p 9090:9090 \
  -p 8080:8080 \
  auth-service:latest
```

#### Run with custom environment variables
```bash
docker run -d \
  --name auth-service \
  -p 9090:9090 \
  -p 8080:8080 \
  -e SERVICE_NAME=my-auth-service \
  -e JAEGER_URL=jaeger:4317 \
  -e METRICS_PATH=/custom-metrics \
  -e GRPC_PORT=9090 \
  -e HTTP_PORT=8080 \
  auth-service:latest
```

#### View logs
```bash
docker logs -f auth-service
```

#### Stop and remove
```bash
docker stop auth-service
docker rm auth-service
```

### Direct Binary Execution

#### Build
```bash
go build -o bin/auth-service ./main.go
```

#### Run
```bash
./bin/auth-service gateway \
  --service-name=auth-service \
  --jaeger-url=localhost:4317 \
  --metrics-path=/metrics \
  --grpc-port=9090 \
  --http-port=8080
```

## Configuration

### Environment Variables (Docker)
- `SERVICE_NAME` - Name of the service (default: `auth-service`)
- `JAEGER_URL` - Jaeger OTLP endpoint (default: `localhost:4317`)
- `METRICS_PATH` - Prometheus metrics path (default: `/metrics`)
- `GRPC_PORT` - gRPC server port (default: `9090`)
- `HTTP_PORT` - HTTP server port (default: `8080`)

### Makefile Variables
Same as environment variables above, can be overridden:
```bash
make run SERVICE_NAME=custom-auth GRPC_PORT=9091
```

## Endpoints

Once running, the service exposes:

### gRPC
- Port: `9090` (default)
- Services:
  - `AuthenticateService`
  - `UserRoleService`

### HTTP (grpc-gateway)
- Port: `8080` (default)
- All gRPC endpoints available via HTTP/REST
- Metrics: `http://localhost:8080/metrics`

## Health Check

The Docker container includes a health check that queries the metrics endpoint:
```bash
curl http://localhost:8080/metrics
```

## Security Features

The Dockerfile includes:
- ✅ Non-root user execution
- ✅ Minimal Alpine base image
- ✅ Multi-stage build for smaller image size
- ✅ Binary stripping for reduced size
- ✅ Health check endpoint
- ✅ Timezone data for proper time handling
