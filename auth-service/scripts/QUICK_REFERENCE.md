# Super-Admin Quick Reference

## Quick Commands

### Initialize Super-Admin
```bash
# Using test script (recommended)
bash scripts/test_super_admin.sh

# Using Go script directly
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
go run scripts/init_super_admin.go
```

### Default Credentials
- **Username:** `superadmin`
- **Password:** `SuperAdmin@123`
- **Email:** `superadmin@system.local`

### Environment Variables
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
export SUPER_ADMIN_EMAIL="superadmin@system.local"
export SUPER_ADMIN_USERNAME="superadmin"
export SUPER_ADMIN_PASSWORD="SuperAdmin@123"
export SUPER_ADMIN_DISPLAY_NAME="Super Administrator"
```

## Files Created

| File | Purpose |
|------|---------|
| `scripts/init_super_admin.go` | Go initialization script (204 lines) |
| `scripts/init-super-admin.sql` | SQL initialization script (71 lines) |
| `scripts/test_super_admin.sh` | Test script (132 lines) |
| `scripts/example_init.sh` | Example usage (30 lines) |
| `scripts/README.md` | Complete documentation |

## Super-Admin Capabilities

✅ Create tenants  
✅ Create tenant admin users  
✅ Manage all system resources  
✅ No tenant restrictions  

## Database Structure

- **User:** tenant_id = NULL
- **Role:** tenant_id = NULL, name = "super-admin"
- **Status:** Active (1)

## Security Notes

⚠️ **Change default password in production!**

For production:
1. Use strong passwords
2. Store in secrets manager
3. Rotate regularly
4. Enable MFA
5. Audit access logs
