package usecases

import (
	"context"
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/blcvn/backend/services/auth-service/entities"
)

type roleUsecase struct {
	role iRoleRepository
	user iUserRepository
}

func NewRoleUsecase(role iRoleRepository, user iUserRepository) *roleUsecase {
	return &roleUsecase{role: role, user: user}
}

func (u *roleUsecase) AssignRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError) {
	// Validate roles exist and belong to tenant
	if err := u.role.ValidateRoles(source.TenantId, source.RoleIds); err != nil {
		return nil, err
	}

	// Deduplicate requested roleIds
	requestedRoleMap := make(map[string]bool)
	for _, roleId := range source.RoleIds {
		requestedRoleMap[roleId] = true
	}

	// Convert map back to slice for UPSERT
	uniqueRoleIds := make([]string, 0, len(requestedRoleMap))
	for roleId := range requestedRoleMap {
		uniqueRoleIds = append(uniqueRoleIds, roleId)
	}

	// UPSERT roles (insert new or reactivate existing in single operation)
	if err := u.role.UpsertRoles(source.UserId, uniqueRoleIds); err != nil {
		return nil, err
	}

	// Return user info with assigned roles
	return &entities.UserInfo{
		UserId:   source.UserId,
		TenantId: source.TenantId,
		Roles:    uniqueRoleIds,
	}, nil
}
func (u *roleUsecase) UnassignRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError) {
	// Validate roles exist and belong to tenant
	if err := u.role.ValidateRoles(source.TenantId, source.RoleIds); err != nil {
		return nil, err
	}

	// Deduplicate requested roleIds
	requestedRoleMap := make(map[string]bool)
	for _, roleId := range source.RoleIds {
		requestedRoleMap[roleId] = true
	}

	// Convert map back to slice
	uniqueRoleIds := make([]string, 0, len(requestedRoleMap))
	for roleId := range requestedRoleMap {
		uniqueRoleIds = append(uniqueRoleIds, roleId)
	}

	// Batch unassign (set status to UNACTIVE)
	// This will only affect existing active roles, safe for non-existent roles
	if err := u.role.UnactiveRoles(source.UserId, uniqueRoleIds); err != nil {
		return nil, err
	}

	// Return user info
	return &entities.UserInfo{
		UserId:   source.UserId,
		TenantId: source.TenantId,
	}, nil
}
func (u *roleUsecase) OverrideRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError) {
	// Validate roles exist and belong to tenant
	if err := u.role.ValidateRoles(source.TenantId, source.RoleIds); err != nil {
		return nil, err
	}

	// Deduplicate requested roleIds
	requestedRoleMap := make(map[string]bool)
	for _, roleId := range source.RoleIds {
		requestedRoleMap[roleId] = true
	}

	// Convert map back to slice
	uniqueRoleIds := make([]string, 0, len(requestedRoleMap))
	for roleId := range requestedRoleMap {
		uniqueRoleIds = append(uniqueRoleIds, roleId)
	}

	// UPSERT new roles (insert new or reactivate existing)
	if err := u.role.UpsertRoles(source.UserId, uniqueRoleIds); err != nil {
		return nil, err
	}

	// Deactivate all roles NOT in the new set
	if err := u.role.UnactiveRolesExcept(source.UserId, uniqueRoleIds); err != nil {
		return nil, err
	}

	// Return user info with new roles
	return &entities.UserInfo{
		UserId:   source.UserId,
		TenantId: source.TenantId,
		Roles:    uniqueRoleIds,
	}, nil
}

func (u *roleUsecase) ActiveUser(tenantId, userId string) (*entities.UserInfo, errors.BaseError) {
	// Update user status to active
	userInfo, err := u.user.UpdateUserStatus(userId, dto.StatusActive)
	if err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (u *roleUsecase) InactiveUser(tenantId, userId string) (*entities.UserInfo, errors.BaseError) {
	// Update user status to inactive
	userInfo, err := u.user.UpdateUserStatus(userId, dto.StatusInactive)
	if err != nil {
		return nil, err
	}
	return userInfo, nil
}

func (u *roleUsecase) ListRoles(ctx context.Context, tenantId string, roleIds []string, pagination *entities.Pagination) ([]*entities.UserInfo, *entities.Pagination, errors.BaseError) {
	// Validate tenant ID
	if tenantId == "" {
		return nil, nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}

	// Validate pagination
	if pagination == nil {
		pagination = &entities.Pagination{
			Page:  1,
			Limit: 10,
			Total: 0,
		}
	}

	// Ensure page and limit are valid
	if pagination.Page < 1 {
		pagination.Page = 1
	}
	if pagination.Limit < 1 || pagination.Limit > 100 {
		pagination.Limit = 10
	}

	// Call repository to get paginated users
	users, updatedPagination, err := u.user.ListUsersByTenant(tenantId, pagination)
	if err != nil {
		return nil, nil, err
	}

	return users, updatedPagination, nil
}
