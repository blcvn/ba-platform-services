package dto

import (
	"time"

	"github.com/google/uuid"
)

type RolePermission struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	TenantID     uuid.UUID `gorm:"type:uuid;not null;index"`
	RoleID       uuid.UUID `gorm:"type:uuid;not null;index"`
	PermissionID uuid.UUID `gorm:"type:uuid;not null;index"`
	CreatedAt    time.Time
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
