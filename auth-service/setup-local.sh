#!/bin/bash
# Local Development Setup Script for Auth Service

set -e

echo "🚀 Setting up Auth Service for local development..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running from correct directory
if [ ! -f "main.go" ]; then
    echo -e "${RED}❌ Error: Please run this script from the auth-service directory${NC}"
    exit 1
fi

# Create config directory if it doesn't exist
mkdir -p config

# Step 1: Create local config file
echo -e "${YELLOW}📝 Creating local configuration files...${NC}"

if [ ! -f "config/config.yaml" ]; then
    cp config/config.local.yaml config/config.yaml
    echo -e "${GREEN}✓ Created config/config.yaml${NC}"
else
    echo -e "${YELLOW}⚠ config/config.yaml already exists, skipping...${NC}"
fi

# Step 2: Create secrets file
SECRETS_FILE="/tmp/auth-service-secrets.json"

if [ ! -f "$SECRETS_FILE" ]; then
    cat > "$SECRETS_FILE" << 'EOF'
{
  "database": {
    "url": "postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable",
    "username": "postgres",
    "password": "postgres"
  },
  "redis": {
    "addr": "localhost:6379",
    "password": "",
    "db": 0
  },
  "jwt_secret": "local-development-jwt-secret-key-must-be-at-least-32-characters-long",
  "super_admin": {
    "email": "superadmin@system.local",
    "username": "superadmin",
    "password": "SuperAdmin@123",
    "display_name": "Super Administrator"
  }
}
EOF
    echo -e "${GREEN}✓ Created $SECRETS_FILE${NC}"
else
    echo -e "${YELLOW}⚠ $SECRETS_FILE already exists, skipping...${NC}"
fi

# Step 3: Create .env file for easy environment variable management
if [ ! -f ".env" ]; then
    cat > .env << EOF
# Auth Service Local Development Environment Variables
SECRET_FILE=$SECRETS_FILE
CONFIG_FILE=./config/config.yaml

# Optional: Override individual secrets (uncomment to use)
# DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable
# REDIS_ADDR=localhost:6379
# JWT_SECRET=local-development-jwt-secret-key-must-be-at-least-32-characters-long

# Service Configuration
SERVICE_NAME=auth-service
JAEGER_URL=localhost:4317
METRICS_PATH=/metrics
GRPC_PORT=9090
HTTP_PORT=8080
EOF
    echo -e "${GREEN}✓ Created .env file${NC}"
else
    echo -e "${YELLOW}⚠ .env already exists, skipping...${NC}"
fi

# Step 4: Check dependencies
echo -e "${YELLOW}🔍 Checking dependencies...${NC}"

# Check if PostgreSQL is running
if command -v psql &> /dev/null; then
    if pg_isready -h localhost -p 5432 &> /dev/null; then
        echo -e "${GREEN}✓ PostgreSQL is running${NC}"
    else
        echo -e "${RED}⚠ PostgreSQL is not running on localhost:5432${NC}"
        echo -e "${YELLOW}  Start it with: docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres${NC}"
    fi
else
    echo -e "${YELLOW}⚠ psql not found, skipping PostgreSQL check${NC}"
fi

# Check if Redis is running
if command -v redis-cli &> /dev/null; then
    if redis-cli -h localhost -p 6379 ping &> /dev/null; then
        echo -e "${GREEN}✓ Redis is running${NC}"
    else
        echo -e "${RED}⚠ Redis is not running on localhost:6379${NC}"
        echo -e "${YELLOW}  Start it with: docker run -d -p 6379:6379 redis${NC}"
    fi
else
    echo -e "${YELLOW}⚠ redis-cli not found, skipping Redis check${NC}"
fi

# Step 5: Download Go dependencies
echo -e "${YELLOW}📦 Downloading Go dependencies...${NC}"
go mod download
go mod tidy
echo -e "${GREEN}✓ Dependencies downloaded${NC}"

# Step 6: Create database if needed
echo -e "${YELLOW}🗄️  Database setup...${NC}"
echo -e "${YELLOW}  To create the database, run:${NC}"
echo -e "${YELLOW}  createdb auth_db${NC}"
echo -e "${YELLOW}  or${NC}"
echo -e "${YELLOW}  docker exec -it <postgres-container> psql -U postgres -c 'CREATE DATABASE auth_db;'${NC}"

# Step 7: Initialize super-admin (optional)
echo ""
echo -e "${YELLOW}🔐 Super-Admin Initialization...${NC}"
echo -e "${YELLOW}  To initialize the super-admin account, run:${NC}"
echo -e "${YELLOW}  export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable${NC}"
echo -e "${YELLOW}  go run scripts/init_super_admin.go${NC}"
echo -e "${YELLOW}  or use the test script:${NC}"
echo -e "${YELLOW}  bash scripts/test_super_admin.sh${NC}"


echo ""
echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo -e "${YELLOW}To run the service:${NC}"
echo -e "  ${GREEN}source .env && make run${NC}"
echo -e "  or"
echo -e "  ${GREEN}export SECRET_FILE=$SECRETS_FILE && make run${NC}"
echo ""
echo -e "${YELLOW}To run with Docker Compose (if available):${NC}"
echo -e "  ${GREEN}make docker-build && make docker-run${NC}"
echo ""
echo -e "${YELLOW}Endpoints:${NC}"
echo -e "  gRPC:   ${GREEN}localhost:9090${NC}"
echo -e "  HTTP:   ${GREEN}localhost:8080${NC}"
echo -e "  Metrics: ${GREEN}http://localhost:8080/metrics${NC}"
echo ""
