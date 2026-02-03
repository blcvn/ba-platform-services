package helper

import (
	"fmt"
	"slices"

	"github.com/blcvn/backend/services/auth-service/common/configs"
	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/entities"
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

func (v *validator) ValidateRegister(source *entities.RegisterPayload) errors.BaseError {
	if source == nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRegisterPayloadRequired))
	}
	if source.TenantId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	if source.Username == "" || source.Password == "" || source.Email == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUsernamePasswordEmailRequired))
	}
	return nil
}

func (v *validator) ValidateLogin(source *entities.LoginPayload) errors.BaseError {
	if source == nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrLoginPayloadRequired))
	}
	if source.TenantId == "" {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	switch source.Method {
	case entities.LoginMethod_USERNAME_PASSWORD:

		if source.Username == "" || source.Password == "" {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUsernamePasswordEmailRequired))
		}
	case entities.LoginMethod_GOOGLE:
		if source.GToken == "" {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrGoogleTokenRequired))
		}
	}
	return nil
}

func (v *validator) ValidateUser(tenantId string, roleIds []string, source *entities.UserInfo) errors.BaseError {
	if source == nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRolePayloadRequired))
	}
	if source.TenantId != tenantId && !slices.Contains(roleIds, configs.RoleCfg.SuperAdminRole) {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	return nil
}

func (v *validator) ValidateRoles(tenantId string, roleIds []string, source *entities.RolePayload) errors.BaseError {
	if source == nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRolePayloadRequired))
	}
	if source.TenantId != tenantId && !slices.Contains(roleIds, configs.RoleCfg.SuperAdminRole) {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrTenantIDRequired))
	}
	return nil
}
