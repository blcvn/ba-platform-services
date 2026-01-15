package helper

import (
	"fmt"

	"github.com/anhdt/golang-enterprise-repo/services/author-service/common/errors"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/entities"
)

type validator struct {
}

func NewValidator() *validator {
	return &validator{}
}

func (v *validator) ValidateMetadata(source *entities.Metadata) errors.BaseError {
	return nil
}
func (v *validator) ValidateSignature(source *entities.Signature) errors.BaseError {
	return nil
}

func (v *validator) ValidateTenant(source *entities.Tenant) errors.BaseError {
	if source.Name == "" {
		return errors.NewBaseError(400, fmt.Errorf("tenant name is required"))
	}
	return nil
}

func (v *validator) ValidateRole(source *entities.Role) errors.BaseError {
	if source.Name == "" {
		return errors.NewBaseError(400, fmt.Errorf("role name is required"))
	}
	if source.TenantId == "" {
		return errors.NewBaseError(400, fmt.Errorf("tenant id is required"))
	}
	return nil
}

func (v *validator) ValidatePermission(source *entities.Permission) errors.BaseError {
	if source.Name == "" {
		return errors.NewBaseError(400, fmt.Errorf("permission name is required"))
	}
	if source.TenantId == "" {
		return errors.NewBaseError(400, fmt.Errorf("tenant id is required"))
	}
	if source.Code == "" {
		return errors.NewBaseError(400, fmt.Errorf("permission code is required"))
	}
	if source.Resource == "" {
		return errors.NewBaseError(400, fmt.Errorf("permission resource is required"))
	}
	if source.Action == "" {
		return errors.NewBaseError(400, fmt.Errorf("permission action is required"))
	}
	return nil
}

func (v *validator) ValidateRolePermission(source *entities.RolePermission) errors.BaseError {
	if source.RoleId == "" {
		return errors.NewBaseError(400, fmt.Errorf("role id is required"))
	}
	if len(source.PermissionIds) == 0 {
		return errors.NewBaseError(400, fmt.Errorf("permission ids are required"))
	}
	return nil
}
