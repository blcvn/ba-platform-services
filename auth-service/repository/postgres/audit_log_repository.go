package postgres

import (
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type auditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) *auditLogRepository {
	return &auditLogRepository{db: db}
}

// CreateAuditLog creates a new audit log entry
func (r *auditLogRepository) CreateAuditLog(auditLog *dto.AuthAuditLog) errors.BaseError {
	if err := r.db.Create(auditLog).Error; err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return nil
}

// GetAuditLogsByUserID retrieves audit logs for a specific user
func (r *auditLogRepository) GetAuditLogsByUserID(userID uuid.UUID, limit int) ([]*dto.AuthAuditLog, errors.BaseError) {
	var logs []*dto.AuthAuditLog
	query := r.db.Where("user_id = ?", userID).Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&logs).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	return logs, nil
}

// GetAuditLogsByTenantID retrieves audit logs for a specific tenant
func (r *auditLogRepository) GetAuditLogsByTenantID(tenantID uuid.UUID, limit int) ([]*dto.AuthAuditLog, errors.BaseError) {
	var logs []*dto.AuthAuditLog
	query := r.db.Where("tenant_id = ?", tenantID).Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&logs).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	return logs, nil
}

// GetAuditLogsByAction retrieves audit logs filtered by action type
func (r *auditLogRepository) GetAuditLogsByAction(tenantID uuid.UUID, action string, limit int) ([]*dto.AuthAuditLog, errors.BaseError) {
	var logs []*dto.AuthAuditLog
	query := r.db.Where("tenant_id = ? AND action = ?", tenantID, action).Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&logs).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	return logs, nil
}

// GetFailedLoginAttempts retrieves failed login attempts for security monitoring
func (r *auditLogRepository) GetFailedLoginAttempts(tenantID uuid.UUID, userID *uuid.UUID, limit int) ([]*dto.AuthAuditLog, errors.BaseError) {
	var logs []*dto.AuthAuditLog
	query := r.db.Where("tenant_id = ? AND action IN (?, ?) AND result = ?",
		tenantID, "LOGIN", "LOGIN_GOOGLE", "failure").Order("created_at DESC")

	if userID != nil {
		query = query.Where("user_id = ?", userID)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&logs).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	return logs, nil
}
