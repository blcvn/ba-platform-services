# Build stage
FROM golang:1.24 as builder
WORKDIR /app

# Copy go.mod files for dependency resolution
COPY services/pkg/go.mod ./services/pkg/
COPY services/session-service/go.mod services/session-service/go.sum ./services/session-service/

# Download dependencies
RUN cd services/session-service && go mod download

# Copy source code
COPY . .

# Build the application
RUN cd services/session-service && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /bin/session-service ./main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl tzdata

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# Create necessary directories
RUN mkdir -p /app/config /vault/secrets && \
    chown -R appuser:appuser /app

# Copy binary from builder
COPY --from=builder /bin/session-service /bin/session-service

# Copy config file from builder
COPY --from=builder /app/services/session-service/config/config.yaml /app/config/config.yaml

# Set ownership
RUN chown appuser:appuser /bin/session-service && \
    chown -R appuser:appuser /app/config

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Environment variables with defaults
ENV SERVICE_NAME=session-service \
    JAEGER_URL=localhost:4317 \
    METRICS_PATH=/metrics \
    GRPC_PORT=9090 \
    HTTP_PORT=8080 \
    CONFIG_FILE=/app/config/config.yaml \
    SECRET_FILE=/vault/secrets/config.json

# Expose ports
EXPOSE 9090 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${HTTP_PORT}/metrics || exit 1

# Run the application with gateway command
CMD ["/bin/session-service", "gateway", \
    "--service-name=${SERVICE_NAME}", \
    "--jaeger-url=${JAEGER_URL}", \
    "--metrics-path=${METRICS_PATH}", \
    "--grpc-port=9090", \
    "--http-port=8080"]
