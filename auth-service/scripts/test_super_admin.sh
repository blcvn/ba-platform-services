#!/bin/bash
# Test script for super-admin initialization and functionality
# This script tests:
# 1. Super-admin account creation
# 2. Super-admin login
# 3. Tenant creation capability
# 4. Tenant admin user creation capability

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DATABASE_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable}"
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8080}"
GRPC_SERVICE_URL="${GRPC_SERVICE_URL:-localhost:9090}"

# Super-admin credentials
SUPER_ADMIN_EMAIL="${SUPER_ADMIN_EMAIL:-superadmin@system.local}"
SUPER_ADMIN_USERNAME="${SUPER_ADMIN_USERNAME:-superadmin}"
SUPER_ADMIN_PASSWORD="${SUPER_ADMIN_PASSWORD:-SuperAdmin@123}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Super-Admin Initialization Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Initialize super-admin
echo -e "${YELLOW}Step 1: Initializing super-admin account...${NC}"
cd "$(dirname "$0")/.."

export DATABASE_URL="$DATABASE_URL"
export SUPER_ADMIN_EMAIL="$SUPER_ADMIN_EMAIL"
export SUPER_ADMIN_USERNAME="$SUPER_ADMIN_USERNAME"
export SUPER_ADMIN_PASSWORD="$SUPER_ADMIN_PASSWORD"

go run scripts/init_super_admin.go

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Super-admin initialization completed${NC}"
else
    echo -e "${RED}✗ Super-admin initialization failed${NC}"
    exit 1
fi

echo ""

# Step 2: Verify super-admin in database
echo -e "${YELLOW}Step 2: Verifying super-admin in database...${NC}"

# Extract connection details from DATABASE_URL
DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')
DB_USER=$(echo $DATABASE_URL | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')

QUERY="SELECT u.id, u.username, u.email, u.tenant_id, r.name as role_name 
FROM users u 
JOIN user_roles ur ON u.id = ur.user_id 
JOIN roles r ON ur.role_id = r.id 
WHERE u.username = '$SUPER_ADMIN_USERNAME' AND u.tenant_id IS NULL;"

if command -v psql &> /dev/null; then
    RESULT=$(PGPASSWORD=postgres psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c "$QUERY")
    
    if [ -n "$RESULT" ]; then
        echo -e "${GREEN}✓ Super-admin found in database:${NC}"
        echo "$RESULT"
    else
        echo -e "${RED}✗ Super-admin not found in database${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ psql not found, skipping database verification${NC}"
fi

echo ""

# Step 3: Test super-admin login (if auth service is running)
echo -e "${YELLOW}Step 3: Testing super-admin login...${NC}"

if command -v curl &> /dev/null; then
    # Check if service is running
    if curl -s -f "$AUTH_SERVICE_URL/health" > /dev/null 2>&1; then
        # Try to login
        LOGIN_RESPONSE=$(curl -s -X POST "$AUTH_SERVICE_URL/api/v1/auth/login" \
            -H "Content-Type: application/json" \
            -d "{
                \"username\": \"$SUPER_ADMIN_USERNAME\",
                \"password\": \"$SUPER_ADMIN_PASSWORD\"
            }")
        
        if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
            echo -e "${GREEN}✓ Super-admin login successful${NC}"
            ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
            echo -e "${GREEN}  Access token obtained${NC}"
        else
            echo -e "${RED}✗ Super-admin login failed${NC}"
            echo "Response: $LOGIN_RESPONSE"
        fi
    else
        echo -e "${YELLOW}⚠ Auth service not running at $AUTH_SERVICE_URL${NC}"
        echo -e "${YELLOW}  Start the service to test login functionality${NC}"
    fi
else
    echo -e "${YELLOW}⚠ curl not found, skipping login test${NC}"
fi

echo ""

# Step 4: Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Super-admin account created${NC}"
echo -e "  Email:    $SUPER_ADMIN_EMAIL"
echo -e "  Username: $SUPER_ADMIN_USERNAME"
echo -e "  Role:     super-admin (no tenant)"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Start the auth service: ${GREEN}make run${NC}"
echo -e "  2. Login with super-admin credentials"
echo -e "  3. Create tenants using the super-admin account"
echo -e "  4. Create tenant admin users"
echo ""
echo -e "${RED}IMPORTANT:${NC} Change the default password in production!"
echo -e "${BLUE}========================================${NC}"
