package postgres

import (
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/blcvn/backend/services/auth-service/entities"
	"github.com/google/uuid"
)

func (r *userRepository) ListUsersByTenant(tenantId string, pagination *entities.Pagination) ([]*entities.UserInfo, *entities.Pagination, errors.BaseError) {
	// Validate inputs
	if tenantId == "" {
		return nil, nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	if pagination == nil {
		pagination = &entities.Pagination{
			Page:  1,
			Limit: 10,
			Total: 0,
		}
	}

	// Parse tenantId to UUID
	tenantUUID, parseErr := uuid.Parse(tenantId)
	if parseErr != nil {
		return nil, nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidTenantIDFormat))
	}

	// Calculate offset
	offset := (pagination.Page - 1) * pagination.Limit

	// Get total count
	var total int64
	if err := r.db.Model(&dto.User{}).Where("tenant_id = ?", tenantUUID).Count(&total).Error; err != nil {
		return nil, nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUser, err))
	}

	// Get paginated users
	var users []dto.User
	if err := r.db.Where("tenant_id = ?", tenantUUID).
		Offset(int(offset)).
		Limit(int(pagination.Limit)).
		Find(&users).Error; err != nil {
		return nil, nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUser, err))
	}

	// Convert to UserInfo entities and fetch roles for each user
	userInfos := make([]*entities.UserInfo, 0, len(users))
	for _, user := range users {
		// Fetch user roles
		var userRoles []dto.UserRole
		if err := r.db.Where("user_id = ? AND status = ?", user.ID, dto.StatusActive).Find(&userRoles).Error; err != nil {
			return nil, nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
		}

		// Extract role IDs
		roles := make([]string, 0, len(userRoles))
		for _, userRole := range userRoles {
			roles = append(roles, userRole.RoleID.String())
		}

		userInfos = append(userInfos, &entities.UserInfo{
			UserId:     user.ID.String(),
			TenantId:   user.TenantID.String(),
			Email:      user.Email,
			Username:   user.Username,
			Status:     user.Status,
			Roles:      roles,
			Attributes: make(map[string]string),
		})
	}

	// Update pagination with total
	updatedPagination := &entities.Pagination{
		Page:  pagination.Page,
		Limit: pagination.Limit,
		Total: total,
	}

	return userInfos, updatedPagination, nil
}
