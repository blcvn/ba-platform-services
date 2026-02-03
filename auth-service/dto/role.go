package dto

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TenantID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_tenant_role_name"`
	Name        string    `gorm:"type:varchar(100);not null;uniqueIndex:idx_tenant_role_name"`
	Description string    `gorm:"type:text"`
	Status      int       `gorm:"type:int;not null;default:1"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}
