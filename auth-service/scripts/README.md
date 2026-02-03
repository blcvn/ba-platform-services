# Super-Admin Initialization Scripts

This directory contains scripts for initializing and testing the super-admin account in the auth service.

## Overview

The super-admin account is a special account that:
- Has **no tenant association** (tenant_id is NULL)
- Has the **super-admin role** with the highest privileges
- Can **create tenants**
- Can **create and manage tenant admin users**
- Is the first account created when initializing the database

## Scripts

### 1. `init_super_admin.go`

Go script that initializes the super-admin account in the database.

**Features:**
- Creates super-admin role (with NULL tenant_id)
- Creates super-admin user (with NULL tenant_id)
- Assigns super-admin role to the user
- Uses bcrypt for password hashing
- Idempotent (can be run multiple times safely)
- Configurable via environment variables

**Usage:**

```bash
# Set environment variables
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
export SUPER_ADMIN_EMAIL="superadmin@system.local"
export SUPER_ADMIN_USERNAME="superadmin"
export SUPER_ADMIN_PASSWORD="SuperAdmin@123"
export SUPER_ADMIN_DISPLAY_NAME="Super Administrator"

# Run the script
go run scripts/init_super_admin.go
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `SUPER_ADMIN_EMAIL` | `superadmin@system.local` | Super-admin email address |
| `SUPER_ADMIN_USERNAME` | `superadmin` | Super-admin username |
| `SUPER_ADMIN_PASSWORD` | `SuperAdmin@123` | Super-admin password (plain text, will be hashed) |
| `SUPER_ADMIN_DISPLAY_NAME` | `Super Administrator` | Super-admin display name |
| `SUPER_ADMIN_ROLE` | `super-admin` | Super-admin role name |

### 2. `init-super-admin.sql`

SQL script for manual super-admin initialization.

**Usage:**

```bash
# Update the bcrypt hash in the SQL file first
# Then run:
psql -h localhost -U postgres -d auth_db -f scripts/init-super-admin.sql
```

**Note:** You need to generate a bcrypt hash for your password and update the SQL file before running.

To generate a bcrypt hash:
```bash
# Using htpasswd
htpasswd -bnBC 10 "" YourPassword | tr -d ':\n'

# Or use the Go script (recommended)
go run scripts/init_super_admin.go
```

### 3. `test_super_admin.sh`

Comprehensive test script that:
1. Initializes the super-admin account
2. Verifies the account in the database
3. Tests login functionality (if auth service is running)

**Usage:**

```bash
# Make the script executable
chmod +x scripts/test_super_admin.sh

# Run the test
bash scripts/test_super_admin.sh
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable` | PostgreSQL connection string |
| `AUTH_SERVICE_URL` | `http://localhost:8080` | Auth service HTTP endpoint |
| `GRPC_SERVICE_URL` | `localhost:9090` | Auth service gRPC endpoint |
| `SUPER_ADMIN_EMAIL` | `superadmin@system.local` | Super-admin email |
| `SUPER_ADMIN_USERNAME` | `superadmin` | Super-admin username |
| `SUPER_ADMIN_PASSWORD` | `SuperAdmin@123` | Super-admin password |

## Quick Start

### Option 1: Using the Test Script (Recommended)

```bash
cd services/auth-service
bash scripts/test_super_admin.sh
```

This will:
- Initialize the super-admin account
- Verify it in the database
- Test login (if service is running)

### Option 2: Using the Go Script Directly

```bash
cd services/auth-service
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
go run scripts/init_super_admin.go
```

### Option 3: Using SQL Script

```bash
# 1. Generate bcrypt hash for your password
htpasswd -bnBC 10 "" YourPassword | tr -d ':\n'

# 2. Update the hash in scripts/init-super-admin.sql

# 3. Run the SQL script
psql -h localhost -U postgres -d auth_db -f scripts/init-super-admin.sql
```

## Integration with Setup

The super-admin initialization is integrated into the local setup workflow:

```bash
# 1. Run the setup script
bash setup-local.sh

# 2. Create the database
createdb auth_db

# 3. Initialize super-admin
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
go run scripts/init_super_admin.go

# 4. Start the service
make run
```

## Security Considerations

> [!WARNING]
> **Change the default password in production!**

The default super-admin credentials are:
- **Username:** `superadmin`
- **Password:** `SuperAdmin@123`

These are suitable for local development only. For production:

1. Use strong, randomly generated passwords
2. Store credentials securely (e.g., in a secrets manager)
3. Rotate passwords regularly
4. Enable MFA if available
5. Audit super-admin access logs

## Database Schema

The super-admin account uses the same tables as regular users but with NULL tenant_id:

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID,  -- NULL for super-admin
    email CITEXT UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- bcrypt hash
    display_name VARCHAR(255),
    status INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Roles Table
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID,  -- NULL for super-admin role
    name VARCHAR(100) NOT NULL,
    description TEXT,
    status INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### User Roles Table
```sql
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    status INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    UNIQUE(user_id, role_id)
);
```

## Troubleshooting

### Script fails with "DATABASE_URL is required"
Make sure to export the DATABASE_URL environment variable:
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
```

### "Super-admin already exists" warning
This is normal if you've run the script before. The script is idempotent and will skip creation if the account already exists.

### Cannot connect to database
Ensure PostgreSQL is running:
```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# Or start with Docker
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres
```

### Login test fails
Make sure the auth service is running:
```bash
make run
```

## Next Steps

After initializing the super-admin:

1. **Login** with super-admin credentials
2. **Create tenants** for your organization
3. **Create tenant admin users** to manage each tenant
4. **Assign appropriate roles** to tenant users
5. **Change the default password** for security

## Support

For issues or questions, please refer to:
- [Auth Service README](../README.md)
- [Environment Variables Guide](../ENVIRONMENT_VARIABLES.md)
- [Quick Reference](../QUICK_REFERENCE.md)
