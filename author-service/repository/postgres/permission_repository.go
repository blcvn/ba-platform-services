package postgres

import (
	"errors"
	"fmt"

	"github.com/anhdt/golang-enterprise-repo/services/author-service/common/constants"
	authErrors "github.com/anhdt/golang-enterprise-repo/services/author-service/common/errors"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/dto"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/entities"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type permissionRepository struct {
	db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) *permissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) Create(permission *entities.Permission) (*entities.Permission, authErrors.BaseError) {
	tenantID, err := uuid.Parse(permission.TenantId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid tenant id"))
	}

	newPermission := &dto.Permission{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        permission.Name,
		Description: permission.Description,
		Code:        permission.Code,
		Resource:    permission.Resource,
		Action:      permission.Action,
		Status:      dto.StatusActive,
	}

	if err := r.db.Create(newPermission).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgCreatePermissionError, err.Error()))
	}

	permission.Id = newPermission.ID.String()
	permission.CreatedAt = newPermission.CreatedAt.Unix()
	permission.UpdatedAt = newPermission.UpdatedAt.Unix()

	return permission, nil
}

func (r *permissionRepository) Update(permission *entities.Permission) (*entities.Permission, authErrors.BaseError) {
	id, err := uuid.Parse(permission.Id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid permission id"))
	}

	updates := map[string]interface{}{}
	if permission.Name != "" {
		updates["name"] = permission.Name
	}
	if permission.Description != "" {
		updates["description"] = permission.Description
	}
	if permission.Resource != "" {
		updates["resource"] = permission.Resource
	}
	if permission.Action != "" {
		updates["action"] = permission.Action
	}

	if err := r.db.Model(&dto.Permission{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgUpdatePermissionError, err.Error()))
	}

	return r.Get(permission.Id)
}

func (r *permissionRepository) Delete(id string) authErrors.BaseError {
	uid, err := uuid.Parse(id)
	if err != nil {
		return authErrors.NewBaseError(400, errors.New("invalid permission id"))
	}

	if err := r.db.Delete(&dto.Permission{}, uid).Error; err != nil {
		return authErrors.NewBaseError(500, fmt.Errorf(constants.MsgDeletePermissionError, err.Error()))
	}
	return nil
}

func (r *permissionRepository) Get(id string) (*entities.Permission, authErrors.BaseError) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid permission id"))
	}

	var t dto.Permission
	if err := r.db.First(&t, uid).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authErrors.NewBaseError(404, errors.New("permission not found"))
		}
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgGetPermissionError, err.Error()))
	}

	return &entities.Permission{
		Id:          t.ID.String(),
		TenantId:    t.TenantID.String(),
		Name:        t.Name,
		Description: t.Description,
		Code:        t.Code,
		Resource:    t.Resource,
		Action:      t.Action,
		CreatedAt:   t.CreatedAt.Unix(),
		UpdatedAt:   t.UpdatedAt.Unix(),
	}, nil
}

func (r *permissionRepository) List(pagination *entities.Pagination) ([]*entities.Permission, *entities.Pagination, authErrors.BaseError) {
	var permissions []dto.Permission
	var total int64

	query := r.db.Model(&dto.Permission{})

	if err := query.Count(&total).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListPermissionError, err.Error()))
	}

	offset := (pagination.Page - 1) * pagination.Limit
	if err := query.Offset(int(offset)).Limit(int(pagination.Limit)).Find(&permissions).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListPermissionError, err.Error()))
	}

	result := make([]*entities.Permission, len(permissions))
	for i, t := range permissions {
		result[i] = &entities.Permission{
			Id:          t.ID.String(),
			TenantId:    t.TenantID.String(),
			Name:        t.Name,
			Description: t.Description,
			Code:        t.Code,
			Resource:    t.Resource,
			Action:      t.Action,
			CreatedAt:   t.CreatedAt.Unix(),
			UpdatedAt:   t.UpdatedAt.Unix(),
		}
	}

	pagination.Total = total
	return result, pagination, nil
}
