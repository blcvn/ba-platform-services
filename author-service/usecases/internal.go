package usecases

import (
	"github.com/blcvn/backend/services/author-service/common/errors"
	"github.com/blcvn/backend/services/author-service/entities"
)

type iTenantRepository interface {
	Create(tenant *entities.Tenant) (*entities.Tenant, errors.BaseError)
	Update(tenant *entities.Tenant) (*entities.Tenant, errors.BaseError)
	Delete(id string) errors.BaseError
	Get(id string) (*entities.Tenant, errors.BaseError)
	List(pagination *entities.Pagination) ([]*entities.Tenant, *entities.Pagination, errors.BaseError)
}

type iRoleRepository interface {
	Create(role *entities.Role) (*entities.Role, errors.BaseError)
	Update(role *entities.Role) (*entities.Role, errors.BaseError)
	Delete(id string) errors.BaseError
	Get(id string) (*entities.Role, errors.BaseError)
	List(pagination *entities.Pagination) ([]*entities.Role, *entities.Pagination, errors.BaseError)
}

type iPermissionRepository interface {
	Create(permission *entities.Permission) (*entities.Permission, errors.BaseError)
	Update(permission *entities.Permission) (*entities.Permission, errors.BaseError)
	Delete(id string) errors.BaseError
	Get(id string) (*entities.Permission, errors.BaseError)
	List(pagination *entities.Pagination) ([]*entities.Permission, *entities.Pagination, errors.BaseError)
}

type iRolePermissionRepository interface {
	Assign(rolePermission *entities.RolePermission) (*entities.RolePermission, errors.BaseError)
	Unassign(rolePermission *entities.RolePermission) (*entities.RolePermission, errors.BaseError)
	Override(rolePermission *entities.RolePermission) (*entities.RolePermission, errors.BaseError)
	GetByRole(roleId string) ([]*entities.RolePermission, errors.BaseError)
}
