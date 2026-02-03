#!/bin/bash
# Quick example script showing how to use the super-admin initialization

set -e

echo "=== Super-Admin Initialization Example ==="
echo ""

# 1. Set environment variables
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
export SUPER_ADMIN_EMAIL="superadmin@system.local"
export SUPER_ADMIN_USERNAME="superadmin"
export SUPER_ADMIN_PASSWORD="SuperAdmin@123"
export SUPER_ADMIN_DISPLAY_NAME="Super Administrator"

# 2. Run the initialization script
echo "Running super-admin initialization..."
go run init_super_admin.go

echo ""
echo "=== Initialization Complete ==="
echo ""
echo "You can now login with:"
echo "  Username: $SUPER_ADMIN_USERNAME"
echo "  Password: $SUPER_ADMIN_PASSWORD"
echo ""
echo "This super-admin account can:"
echo "  ✓ Create tenants"
echo "  ✓ Create tenant admin users"
echo "  ✓ Manage all system resources"
