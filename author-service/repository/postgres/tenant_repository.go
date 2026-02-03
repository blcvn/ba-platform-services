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

type tenantRepository struct {
	db *gorm.DB
}

func NewTenantRepository(db *gorm.DB) *tenantRepository {
	return &tenantRepository{db: db}
}

func (r *tenantRepository) Create(tenant *entities.Tenant) (*entities.Tenant, authErrors.BaseError) {
	newTenant := &dto.Tenant{
		ID:          uuid.New(),
		Name:        tenant.Name,
		Description: tenant.Description,
		Status:      dto.StatusActive,
		RefID:       tenant.RefId,
	}

	if err := r.db.Create(newTenant).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgCreateTenantError, err.Error()))
	}

	// Retrieve the newly created tenant from database
	return r.Get(newTenant.ID.String())
}

func (r *tenantRepository) Update(tenant *entities.Tenant) (*entities.Tenant, authErrors.BaseError) {
	id, err := uuid.Parse(tenant.Id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid tenant id"))
	}

	updates := map[string]interface{}{}
	if tenant.Name != "" {
		updates["name"] = tenant.Name
	}
	if tenant.Description != "" {
		updates["description"] = tenant.Description
	}

	if err := r.db.Model(&dto.Tenant{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgUpdateTenantError, err.Error()))
	}

	return r.Get(tenant.Id)
}

func (r *tenantRepository) Delete(id string) authErrors.BaseError {
	uid, err := uuid.Parse(id)
	if err != nil {
		return authErrors.NewBaseError(400, errors.New("invalid tenant id"))
	}

	if err := r.db.Delete(&dto.Tenant{}, uid).Error; err != nil {
		return authErrors.NewBaseError(500, fmt.Errorf(constants.MsgDeleteTenantError, err.Error()))
	}
	return nil
}

func (r *tenantRepository) Get(id string) (*entities.Tenant, authErrors.BaseError) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, authErrors.NewBaseError(400, errors.New("invalid tenant id"))
	}

	var t dto.Tenant
	if err := r.db.First(&t, uid).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authErrors.NewBaseError(404, errors.New("tenant not found"))
		}
		return nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgGetTenantError, err.Error()))
	}

	return &entities.Tenant{
		Id:          t.ID.String(),
		Name:        t.Name,
		Description: t.Description,
		Status:      int(t.Status),
		RefId:       t.RefID,
		CreatedAt:   t.CreatedAt.Unix(),
		UpdatedAt:   t.UpdatedAt.Unix(),
	}, nil
}

func (r *tenantRepository) List(pagination *entities.Pagination) ([]*entities.Tenant, *entities.Pagination, authErrors.BaseError) {
	var tenants []dto.Tenant
	var total int64

	if pagination == nil {
		pagination = &entities.Pagination{
			Page:  1,
			Limit: 10,
		}
	} else {
		if pagination.Page <= 0 {
			pagination.Page = 1
		}
		if pagination.Limit <= 0 {
			pagination.Limit = 10
		}
	}

	query := r.db.Model(&dto.Tenant{})

	if err := query.Count(&total).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListTenantError, err.Error()))
	}

	offset := (pagination.Page - 1) * pagination.Limit
	if err := query.Offset(int(offset)).Limit(int(pagination.Limit)).Find(&tenants).Error; err != nil {
		return nil, nil, authErrors.NewBaseError(500, fmt.Errorf(constants.MsgListTenantError, err.Error()))
	}

	result := make([]*entities.Tenant, len(tenants))
	for i, t := range tenants {
		result[i] = &entities.Tenant{
			Id:          t.ID.String(),
			Name:        t.Name,
			Description: t.Description,
			Status:      int(t.Status),
			RefId:       t.RefID,
			CreatedAt:   t.CreatedAt.Unix(),
			UpdatedAt:   t.UpdatedAt.Unix(),
		}
	}

	pagination.Total = total
	return result, pagination, nil
}
