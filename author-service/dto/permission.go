package dto

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Permission struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	TenantID    uuid.UUID `gorm:"type:uuid;not null;index"`
	Name        string    `gorm:"type:varchar(255);not null"`
	Description string    `gorm:"type:text"`
	Code        string    `gorm:"type:varchar(100);not null;index"` // For programmatic checks
	Resource    string    `gorm:"type:varchar(255)"`
	Action      string    `gorm:"type:varchar(100)"`
	Status      Status    `gorm:"type:smallint;default:1"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (Permission) TableName() string {
	return "permissions"
}
