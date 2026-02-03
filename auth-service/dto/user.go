package dto

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID  `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TenantID    *uuid.UUID `gorm:"type:uuid;index"` // Nullable for super-admin/BA Agent users
	Email       string     `gorm:"type:citext;uniqueIndex;not null"`
	Username    string     `gorm:"type:varchar(255);uniqueIndex;not null"`
	Password    *string    `gorm:"type:varchar(255)"` // Nullable for OAuth-only users
	DisplayName string     `gorm:"type:varchar(255)"`
	AvatarURL   *string    `gorm:"type:text"`                     // NEW: Avatar URL from OAuth provider
	GoogleID    *string    `gorm:"type:varchar(255);uniqueIndex"` // NEW: Google OAuth subject ID
	Status      int        `gorm:"type:int;not null;default:1"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime"`
}

type UserRole struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_unique"`
	RoleID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_unique"`
	Status    int       `gorm:"type:int;not null;default:1"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
