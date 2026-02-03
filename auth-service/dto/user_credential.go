package dto

import (
	"time"

	"github.com/google/uuid"
)

type UserCredential struct {
	ID         uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index"`
	Provider   string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_provider_identifier"` // password | google
	Identifier string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_provider_identifier"`
	SecretHash *string   `gorm:"type:varchar(255)"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
}
