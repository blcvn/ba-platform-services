package dto

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Code      string    `gorm:"type:varchar(100);uniqueIndex;not null"`
	Name      string    `gorm:"type:varchar(255);not null"`
	Status    int       `gorm:"type:int;not null;default:1"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
