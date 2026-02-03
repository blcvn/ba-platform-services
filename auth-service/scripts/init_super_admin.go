package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// User represents the users table
type User struct {
	ID          uuid.UUID  `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TenantID    *uuid.UUID `gorm:"type:uuid;index"` // NULL for super-admin
	Email       string     `gorm:"type:citext;uniqueIndex;not null"`
	Username    string     `gorm:"type:varchar(255);uniqueIndex;not null"`
	Password    string     `gorm:"type:varchar(255);not null"`
	DisplayName string     `gorm:"type:varchar(255)"`
	Status      int        `gorm:"type:int;not null;default:1"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime"`
}

// Role represents the roles table
type Role struct {
	ID          uuid.UUID  `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TenantID    *uuid.UUID `gorm:"type:uuid;index"` // NULL for super-admin role
	Name        string     `gorm:"type:varchar(100);not null"`
	Description string     `gorm:"type:text"`
	Status      int        `gorm:"type:int;not null;default:1"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime"`
}

// UserRole represents the user_roles table
type UserRole struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_unique"`
	RoleID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_unique"`
	Status    int       `gorm:"type:int;not null;default:1"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

const (
	StatusActive   = 1
	StatusInactive = 0
)

type SuperAdminConfig struct {
	Email       string
	Username    string
	Password    string
	DisplayName string
	RoleName    string
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	// Get super-admin configuration from environment
	config := SuperAdminConfig{
		Email:       getEnvOrDefault("SUPER_ADMIN_EMAIL", "superadmin@system.local"),
		Username:    getEnvOrDefault("SUPER_ADMIN_USERNAME", "superadmin"),
		Password:    getEnvOrDefault("SUPER_ADMIN_PASSWORD", "SuperAdmin@123"),
		DisplayName: getEnvOrDefault("SUPER_ADMIN_DISPLAY_NAME", "Super Administrator"),
		RoleName:    getEnvOrDefault("SUPER_ADMIN_ROLE", "super-admin"),
	}

	// Connect to database
	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("✓ Connected to database")

	// Initialize super-admin
	if err := initializeSuperAdmin(db, config); err != nil {
		log.Fatalf("Failed to initialize super-admin: %v", err)
	}

	log.Println("✅ Super-admin initialization completed successfully!")
}

func initializeSuperAdmin(db *gorm.DB, config SuperAdminConfig) error {
	ctx := context.Background()

	// Check if super-admin role already exists
	var existingRole Role
	err := db.WithContext(ctx).Where("name = ? AND tenant_id IS NULL", config.RoleName).First(&existingRole).Error

	var roleID uuid.UUID
	if err == gorm.ErrRecordNotFound {
		// Create super-admin role
		role := Role{
			TenantID:    nil, // NULL for super-admin role
			Name:        config.RoleName,
			Description: "Super Administrator role with highest privileges",
			Status:      StatusActive,
		}

		if err := db.WithContext(ctx).Create(&role).Error; err != nil {
			return fmt.Errorf("failed to create super-admin role: %w", err)
		}

		roleID = role.ID
		log.Printf("✓ Created super-admin role: %s (ID: %s)", config.RoleName, roleID)
	} else if err != nil {
		return fmt.Errorf("failed to check existing super-admin role: %w", err)
	} else {
		roleID = existingRole.ID
		log.Printf("⚠ Super-admin role already exists: %s (ID: %s)", config.RoleName, roleID)
	}

	// Check if super-admin user already exists
	var existingUser User
	err = db.WithContext(ctx).Where("username = ? OR email = ?", config.Username, config.Email).First(&existingUser).Error

	var userID uuid.UUID
	if err == gorm.ErrRecordNotFound {
		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(config.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		// Create super-admin user
		user := User{
			TenantID:    nil, // NULL for super-admin user
			Email:       config.Email,
			Username:    config.Username,
			Password:    string(hashedPassword),
			DisplayName: config.DisplayName,
			Status:      StatusActive,
		}

		if err := db.WithContext(ctx).Create(&user).Error; err != nil {
			return fmt.Errorf("failed to create super-admin user: %w", err)
		}

		userID = user.ID
		log.Printf("✓ Created super-admin user: %s (ID: %s)", config.Username, userID)
	} else if err != nil {
		return fmt.Errorf("failed to check existing super-admin user: %w", err)
	} else {
		userID = existingUser.ID
		log.Printf("⚠ Super-admin user already exists: %s (ID: %s)", config.Username, userID)
	}

	// Check if user-role assignment already exists
	var existingUserRole UserRole
	err = db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).First(&existingUserRole).Error

	if err == gorm.ErrRecordNotFound {
		// Assign super-admin role to user
		userRole := UserRole{
			UserID: userID,
			RoleID: roleID,
			Status: StatusActive,
		}

		if err := db.WithContext(ctx).Create(&userRole).Error; err != nil {
			return fmt.Errorf("failed to assign super-admin role to user: %w", err)
		}

		log.Printf("✓ Assigned super-admin role to user")
	} else if err != nil {
		return fmt.Errorf("failed to check existing user-role assignment: %w", err)
	} else {
		log.Printf("⚠ Super-admin role already assigned to user")
	}

	// Print summary
	log.Println("\n=== Super-Admin Account Details ===")
	log.Printf("Email:        %s", config.Email)
	log.Printf("Username:     %s", config.Username)
	log.Printf("Display Name: %s", config.DisplayName)
	log.Printf("Role:         %s", config.RoleName)
	log.Printf("User ID:      %s", userID)
	log.Printf("Role ID:      %s", roleID)
	log.Println("===================================")

	return nil
}
