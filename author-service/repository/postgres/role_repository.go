package postgres

import (
	"errors"
	"fmt"

	"github.com/blcvn/backend/services/author-service/common/constants"
	authErrors "github.com/blcvn/backend/services/author-service/common/errors"
	"github.com/blcvn/backend/services/author-service/dto"
	"github.com/blcvn/backend/services/author-service/entities"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *roleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(role *entities.Role) (*entities.Role, authErrors.BaseError) {
	tenantID, err := uuid.Parse(role.TenantId)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid tenant id"))
	}

	newRole := &dto.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        role.Name,
		Description: role.Description,
		Status:      dto.StatusActive,
	}

	if err := r.db.Create(newRole).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgCreateRoleError, err.Error()))
	}

	role.Id = newRole.ID.String()
	role.CreatedAt = newRole.CreatedAt.Unix()
	role.UpdatedAt = newRole.UpdatedAt.Unix()

	return role, nil
}

func (r *roleRepository) Update(role *entities.Role) (*entities.Role, authErrors.BaseError) {
	id, err := uuid.Parse(role.Id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	updates := map[string]interface{}{}
	if role.Name != "" {
		updates["name"] = role.Name
	}
	if role.Description != "" {
		updates["description"] = role.Description
	}

	if err := r.db.Model(&dto.Role{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgUpdateRoleError, err.Error()))
	}

	return r.Get(role.Id)
}

func (r *roleRepository) Delete(id string) authErrors.BaseError {
	uid, err := uuid.Parse(id)
	if err != nil {
		return authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	if err := r.db.Delete(&dto.Role{}, uid).Error; err != nil {
		return authErrors.NewBaseError(500, fmt.Errorf(constants.MsgDeleteRoleError, err.Error()))
	}
	return nil
}

func (r *roleRepository) Get(id string) (*entities.Role, authErrors.BaseError) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid role id"))
	}

	var t dto.Role
	if err := r.db.First(&t, uid).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authErrors.NewBaseError(404, errors.New("role not found"))
		}
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgGetRoleError, err.Error()))
	}

	return &entities.Role{
		Id:          t.ID.String(),
		TenantId:    t.TenantID.String(),
		Name:        t.Name,
		Description: t.Description,
		Status:      int(t.Status),
		CreatedAt:   t.CreatedAt.Unix(),
		UpdatedAt:   t.UpdatedAt.Unix(),
	}, nil
}

func (r *roleRepository) List(pagination *entities.Pagination) ([]*entities.Role, *entities.Pagination, authErrors.BaseError) {
	var roles []dto.Role
	var total int64

	query := r.db.Model(&dto.Role{})

	if err := query.Count(&total).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListRoleError, err.Error()))
	}

	offset := (pagination.Page - 1) * pagination.Limit
	if err := query.Offset(int(offset)).Limit(int(pagination.Limit)).Find(&roles).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListRoleError, err.Error()))
	}

	result := make([]*entities.Role, len(roles))
	for i, t := range roles {
		result[i] = &entities.Role{
			Id:          t.ID.String(),
			TenantId:    t.TenantID.String(),
			Name:        t.Name,
			Description: t.Description,
			Status:      int(t.Status),
			CreatedAt:   t.CreatedAt.Unix(),
			UpdatedAt:   t.UpdatedAt.Unix(),
		}
	}

	pagination.Total = total
	return result, pagination, nil
}
