package dto

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Status int

const (
	StatusInactive Status = 0
	StatusActive   Status = 1
)

type Tenant struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string    `gorm:"type:varchar(255);not null"`
	Description string    `gorm:"type:text"`
	Status      Status    `gorm:"type:smallint;default:1"`
	RefID       string    `gorm:"type:varchar(255)"` // For checking duplicates or references
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (Tenant) TableName() string {
	return "tenants"
}
