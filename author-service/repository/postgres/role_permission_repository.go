package postgres

import (
	"errors"
	"fmt"
	"time"

	"github.com/anhdt/golang-enterprise-repo/services/author-service/common/constants"
	authErrors "github.com/anhdt/golang-enterprise-repo/services/author-service/common/errors"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/dto"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/entities"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type rolePermissionRepository struct {
	db *gorm.DB
}

func NewRolePermissionRepository(db *gorm.DB) *rolePermissionRepository {
	return &rolePermissionRepository{db: db}
}

func (r *rolePermissionRepository) Assign(rp *entities.RolePermission) (*entities.RolePermission, authErrors.BaseError) {
	roleID, err := uuid.Parse(rp.RoleId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	// Assign multiple permissions to a role
	for _, permId := range rp.PermissionIds {
		permID, err := uuid.Parse(permId)
		if err != nil {
			return nil, authErrors.NewBaseError(400, fmt.Errorf("invalid permission id: %s", permId))
		}

		// Check if already exists
		var existing dto.RolePermission
		if err := r.db.Where("role_id = ? AND permission_id = ?", roleID, permID).First(&existing).Error; err == nil {
			// Already exists, skip
			continue
		}

		newRP := &dto.RolePermission{
			ID:           uuid.New(),
			RoleID:       roleID,
			PermissionID: permID,
			CreatedAt:    time.Now(),
		}

		if err := r.db.Create(newRP).Error; err != nil {
			return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgAssignPermissionError, err.Error()))
		}
	}

	return rp, nil
}

func (r *rolePermissionRepository) Unassign(rp *entities.RolePermission) (*entities.RolePermission, authErrors.BaseError) {
	roleID, err := uuid.Parse(rp.RoleId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	// Unassign multiple permissions from a role
	for _, permId := range rp.PermissionIds {
		permID, err := uuid.Parse(permId)
		if err != nil {
			return nil, authErrors.NewBaseError(400, fmt.Errorf("invalid permission id: %s", permId))
		}

		if err := r.db.Where("role_id = ? AND permission_id = ?", roleID, permID).Delete(&dto.RolePermission{}).Error; err != nil {
			return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgUnassignPermissionError, err.Error()))
		}
	}

	return rp, nil
}

func (r *rolePermissionRepository) Override(rp *entities.RolePermission) (*entities.RolePermission, authErrors.BaseError) {
	roleID, err := uuid.Parse(rp.RoleId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	// Start a transaction
	tx := r.db.Begin()
	if tx.Error != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf("failed to start transaction: %v", tx.Error))
	}

	// Delete all existing permissions for this role
	if err := tx.Where("role_id = ?", roleID).Delete(&dto.RolePermission{}).Error; err != nil {
		tx.Rollback()
		return nil, authErrors.NewBaseError(500, fmt.Errorf("failed to delete existing permissions: %v", err))
	}

	// Assign new permissions
	for _, permId := range rp.PermissionIds {
		permID, err := uuid.Parse(permId)
		if err != nil {
			tx.Rollback()
			return nil, authErrors.NewBaseError(400, fmt.Errorf("invalid permission id: %s", permId))
		}

		newRP := &dto.RolePermission{
			ID:           uuid.New(),
			RoleID:       roleID,
			PermissionID: permID,
			CreatedAt:    time.Now(),
		}

		if err := tx.Create(newRP).Error; err != nil {
			tx.Rollback()
			return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgAssignPermissionError, err.Error()))
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf("failed to commit transaction: %v", err))
	}

	return rp, nil
}

func (r *rolePermissionRepository) GetByRole(roleId string) ([]*entities.RolePermission, authErrors.BaseError) {
	roleID, err := uuid.Parse(roleId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	var rps []dto.RolePermission
	if err := r.db.Where("role_id = ?", roleID).Find(&rps).Error; err != nil {
		return nil, authErrors.NewBaseError(500, errors.New("failed to get role permissions"))
	}

	// Group permissions by role
	if len(rps) == 0 {
		return []*entities.RolePermission{}, nil
	}

	permissionIds := make([]string, len(rps))
	for i, item := range rps {
		permissionIds[i] = item.PermissionID.String()
	}

	result := []*entities.RolePermission{
		{
			RoleId:        roleId,
			PermissionIds: permissionIds,
		},
	}

	return result, nil
}
