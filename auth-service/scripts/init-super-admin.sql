-- Super Admin Initialization Script
-- This script creates a super-admin account with no tenant association
-- Run this script after database schema is created

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create super-admin role (no tenant association)
-- Note: Replace the role name if needed via environment variable
INSERT INTO roles (id, tenant_id, name, description, status, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    NULL, -- No tenant for super-admin role
    'super-admin',
    'Super Administrator role with highest privileges - can create tenants and manage all users',
    1, -- Active status
    NOW(),
    NOW()
)
ON CONFLICT (name) WHERE tenant_id IS NULL DO NOTHING;

-- Create super-admin user (no tenant association)
-- Note: Password hash is for 'SuperAdmin@123' - CHANGE THIS IN PRODUCTION!
-- To generate a new bcrypt hash, use: htpasswd -bnBC 10 "" your_password | tr -d ':\n'
-- Or use the Go script: go run scripts/init_super_admin.go
INSERT INTO users (id, tenant_id, email, username, password, display_name, status, created_at, updated_at)
VALUES (
    uuid_generate_v4(),
    NULL, -- No tenant for super-admin user
    'superadmin@system.local',
    'superadmin',
    '$2a$10$YourBcryptHashHere', -- Replace with actual bcrypt hash
    'Super Administrator',
    1, -- Active status
    NOW(),
    NOW()
)
ON CONFLICT (username) DO NOTHING;

-- Assign super-admin role to super-admin user
INSERT INTO user_roles (id, user_id, role_id, status, created_at, updated_at)
SELECT 
    uuid_generate_v4(),
    u.id,
    r.id,
    1, -- Active status
    NOW(),
    NOW()
FROM users u
CROSS JOIN roles r
WHERE u.username = 'superadmin' 
  AND u.tenant_id IS NULL
  AND r.name = 'super-admin'
  AND r.tenant_id IS NULL
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Verify the super-admin was created
SELECT 
    u.id as user_id,
    u.username,
    u.email,
    u.display_name,
    r.id as role_id,
    r.name as role_name,
    ur.status as assignment_status
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.tenant_id IS NULL 
  AND r.tenant_id IS NULL
  AND u.username = 'superadmin';
