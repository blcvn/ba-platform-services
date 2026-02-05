package dto

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type AuthAuditLog struct {
	ID           uuid.UUID              `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TenantID     uuid.UUID              `gorm:"type:uuid;not null;index"`
	UserID       *uuid.UUID             `gorm:"type:uuid;index"`
	SessionID    *uuid.UUID             `gorm:"type:uuid;index"`
	Action       string                 `gorm:"type:varchar(100);not null;index"`
	ResourceType string                 `gorm:"type:varchar(100);index"`
	ResourceID   *uuid.UUID             `gorm:"type:uuid;index"`
	IPAddress    net.IP                 `gorm:"type:inet"`
	UserAgent    string                 `gorm:"type:text"`
	Result       string                 `gorm:"type:varchar(50);not null;default:'success';index"` // success, failure, error
	Metadata     map[string]interface{} `gorm:"type:jsonb"`
	Status       int                    `gorm:"type:int;not null;default:1"`
	CreatedAt    time.Time              `gorm:"autoCreateTime;index"`
	UpdatedAt    time.Time              `gorm:"autoUpdateTime"`
}

func (AuthAuditLog) TableName() string {
	return "audit_logs"
}
