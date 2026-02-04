package postgres

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	ID               string  `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	ProjectID        string  `gorm:"type:uuid;not null"`
	CurrentFeatureID *string `gorm:"type:uuid"`
	Status           string  `gorm:"type:varchar(20);default:'active'"` // active, paused, completed
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        gorm.DeletedAt `gorm:"index"`
}
