package postgres

import (
	"fmt"
	"time"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *roleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) GetRoles(userId string) ([]string, errors.BaseError) {
	// Validate input
	if userId == "" {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Query UserRole records for the given userId
	var userRoles []dto.UserRole
	if err := r.db.Where("user_id = ?", userUUID).Find(&userRoles).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
	}

	// Extract roleIds and convert to strings
	roleIds := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		roleIds = append(roleIds, userRole.RoleID.String())
	}

	return roleIds, nil
}

func (r *roleRepository) ValidateRoles(tenantId string, roleIds []string) errors.BaseError {
	// Validate inputs
	if tenantId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	if len(roleIds) == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRoleIDsCannotBeEmpty))
	}

	// Parse tenantId to UUID
	tenantUUID, err := uuid.Parse(tenantId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidTenantIDFormat))
	}

	// Validate tenant exists and is active
	var tenantCount int64
	if err := r.db.Model(&dto.Tenant{}).
		Where("id = ? AND status = ?", tenantUUID, dto.StatusActive).
		Count(&tenantCount).Error; err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryTenant, err))
	}
	if tenantCount == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantNotFoundOrNotActive))
	}

	// Parse roleIds to UUIDs
	roleUUIDs := make([]uuid.UUID, 0, len(roleIds))
	for _, roleId := range roleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}
		roleUUIDs = append(roleUUIDs, roleUUID)
	}

	// Validate all roles exist with the given tenantId and are active
	var roleCount int64
	if err := r.db.Model(&dto.Role{}).
		Where("id IN ? AND tenant_id = ? AND status = ?", roleUUIDs, tenantUUID, dto.StatusActive).
		Count(&roleCount).Error; err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryRoles, err))
	}
	if roleCount != int64(len(roleIds)) {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRolesNotFoundOrInvalid))
	}

	return nil
}

func (r *roleRepository) UpsertRoles(userId string, roleIds []string) errors.BaseError {
	// Validate inputs
	if userId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}
	if len(roleIds) == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRoleIDsCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Parse roleIds to UUIDs and build UserRole records
	userRoles := make([]dto.UserRole, 0, len(roleIds))
	for _, roleId := range roleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}

		userRoles = append(userRoles, dto.UserRole{
			UserID: userUUID,
			RoleID: roleUUID,
			Status: dto.StatusActive,
		})
	}

	// UPSERT: Insert new records or update existing ones to ACTIVE status
	// ON CONFLICT (user_id, role_id) DO UPDATE SET status = 'ACTIVE', updated_at = NOW()
	result := r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "role_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "updated_at"}),
	}).Create(&userRoles)

	if result.Error != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToUpsertUserRoles, result.Error))
	}

	return nil
}

func (r *roleRepository) AddRoles(userId string, roleIds []string) errors.BaseError {
	// Validate inputs
	if userId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}
	if len(roleIds) == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRoleIDsCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Prepare UserRole records for batch insertion
	userRoles := make([]dto.UserRole, 0, len(roleIds))
	for _, roleId := range roleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}

		userRoles = append(userRoles, dto.UserRole{
			UserID: userUUID,
			RoleID: roleUUID,
			Status: dto.StatusActive,
		})
	}

	// Batch insert UserRole records
	if err := r.db.Create(&userRoles).Error; err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToUpsertUserRoles, err))
	}

	return nil
}

func (r *roleRepository) UnactiveRoles(userId string, roleIds []string) errors.BaseError {
	// Validate inputs
	if userId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}
	if len(roleIds) == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRoleIDsCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Parse roleIds to UUIDs
	roleUUIDs := make([]uuid.UUID, 0, len(roleIds))
	for _, roleId := range roleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}
		roleUUIDs = append(roleUUIDs, roleUUID)
	}

	// Update status to UNACTIVE for matching UserRole records
	result := r.db.Model(&dto.UserRole{}).
		Where("user_id = ? AND role_id IN ?", userUUID, roleUUIDs).
		Update("status", dto.StatusInactive)

	if result.Error != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToUpsertUserRoles, result.Error))
	}

	return nil
}

func (r *roleRepository) ReactiveRoles(userId string, roleIds []string) errors.BaseError {
	// Validate inputs
	if userId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}
	if len(roleIds) == 0 {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRoleIDsCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Parse roleIds to UUIDs
	roleUUIDs := make([]uuid.UUID, 0, len(roleIds))
	for _, roleId := range roleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}
		roleUUIDs = append(roleUUIDs, roleUUID)
	}

	// Update status to UNACTIVE for matching UserRole records
	result := r.db.Model(&dto.UserRole{}).
		Where("user_id = ? AND role_id IN ?", userUUID, roleUUIDs).
		Update("status", dto.StatusActive)

	if result.Error != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToUpsertUserRoles, result.Error))
	}
	return nil
}

func (r *roleRepository) UnactiveRolesExcept(userId string, exceptRoleIds []string) errors.BaseError {
	// Validate inputs
	if userId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserIDCannotBeEmpty))
	}

	// Parse userId to UUID
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Handle empty exceptRoleIds (deactivate all roles)
	if len(exceptRoleIds) == 0 {
		result := r.db.Model(&dto.UserRole{}).
			Where("user_id = ? AND status = ?", userUUID, dto.StatusActive).
			Updates(map[string]interface{}{
				"status":     dto.StatusInactive,
				"updated_at": time.Now(),
			})

		if result.Error != nil {
			return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToDeleteUserRoles, result.Error))
		}
		return nil
	}

	// Parse exceptRoleIds to UUIDs
	exceptUUIDs := make([]uuid.UUID, 0, len(exceptRoleIds))
	for _, roleId := range exceptRoleIds {
		roleUUID, err := uuid.Parse(roleId)
		if err != nil {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRoleIDFormat, roleId))
		}
		exceptUUIDs = append(exceptUUIDs, roleUUID)
	}

	// Deactivate all roles NOT in the except list
	result := r.db.Model(&dto.UserRole{}).
		Where("user_id = ? AND role_id NOT IN ? AND status = ?", userUUID, exceptUUIDs, dto.StatusActive).
		Updates(map[string]interface{}{
			"status":     dto.StatusInactive,
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToDeleteUserRoles, result.Error))
	}

	return nil
}
