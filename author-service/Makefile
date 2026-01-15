.PHONY: help build run test clean docker-build docker-run docker-stop proto mock

# Variables
APP_NAME=author-service
MAIN_PATH=./main.go
BUILD_DIR=./bin
DOCKER_IMAGE=author-service:latest
GRPC_PORT?=9091
HTTP_PORT?=8081
JAEGER_URL?=localhost:4317
METRICS_PATH?=/metrics
SERVICE_NAME?=author-service
CONFIG_FILE?=./config/config.yaml
SECRET_FILE?=/tmp/author-service-secrets.json

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build the application binary
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

run: ## Run the application with default settings
	@echo "Running $(APP_NAME) gateway..."
	@echo "CONFIG_FILE=$(CONFIG_FILE)"
	@echo "SECRET_FILE=$(SECRET_FILE)"
	@CONFIG_FILE=$(CONFIG_FILE) SECRET_FILE=$(SECRET_FILE) \
	go run $(MAIN_PATH) gateway \
		--service-name=$(SERVICE_NAME) \
		--jaeger-url=$(JAEGER_URL) \
		--metrics-path=$(METRICS_PATH) \
		--grpc-port=$(GRPC_PORT) \
		--http-port=$(HTTP_PORT)

run-binary: build ## Build and run the binary
	@echo "Running $(APP_NAME) binary..."
	@echo "CONFIG_FILE=$(CONFIG_FILE)"
	@echo "SECRET_FILE=$(SECRET_FILE)"
	@CONFIG_FILE=$(CONFIG_FILE) SECRET_FILE=$(SECRET_FILE) \
	$(BUILD_DIR)/$(APP_NAME) gateway \
		--service-name=$(SERVICE_NAME) \
		--jaeger-url=$(JAEGER_URL) \
		--metrics-path=$(METRICS_PATH) \
		--grpc-port=$(GRPC_PORT) \
		--http-port=$(HTTP_PORT)

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

mock: ## Generate mocks using mockery
	@echo "Generating mocks..."
	@mockery --all --output=./mocks --case=underscore

proto: ## Generate protobuf files (if needed)
	@echo "Generating protobuf files..."
	@cd ../../protos && make go

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE) -f Dockerfile ../../
	@echo "Docker image built: $(DOCKER_IMAGE)"

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -d \
		--name $(APP_NAME) \
		-p $(GRPC_PORT):9091 \
		-p $(HTTP_PORT):8081 \
		-e SERVICE_NAME=$(SERVICE_NAME) \
		-e JAEGER_URL=$(JAEGER_URL) \
		-e METRICS_PATH=$(METRICS_PATH) \
		-e GRPC_PORT=9091 \
		-e HTTP_PORT=8081 \
		-e CONFIG_FILE=/app/config/config.yaml \
		-e SECRET_FILE=/vault/secrets/config.json \
		-v $(PWD)/config/config.yaml:/app/config/config.yaml:ro \
		-v $(SECRET_FILE):/vault/secrets/config.json:ro \
		$(DOCKER_IMAGE)
	@echo "Container started: $(APP_NAME)"

docker-stop: ## Stop and remove Docker container
	@echo "Stopping Docker container..."
	@docker stop $(APP_NAME) || true
	@docker rm $(APP_NAME) || true
	@echo "Container stopped and removed"

docker-logs: ## View Docker container logs
	@docker logs -f $(APP_NAME)

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies updated"

lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

all: clean deps fmt vet test build ## Run all checks and build
