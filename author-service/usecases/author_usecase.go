package usecases

import (
	"context"

	"github.com/anhdt/golang-enterprise-repo/services/author-service/common/errors"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/entities"
)

type AuthorUsecase struct {
	tenantRepo         iTenantRepository
	roleRepo           iRoleRepository
	permissionRepo     iPermissionRepository
	rolePermissionRepo iRolePermissionRepository
}

func NewAuthorUsecase(
	tenantRepo iTenantRepository,
	roleRepo iRoleRepository,
	permissionRepo iPermissionRepository,
	rolePermissionRepo iRolePermissionRepository,
) *AuthorUsecase {
	return &AuthorUsecase{
		tenantRepo:         tenantRepo,
		roleRepo:           roleRepo,
		permissionRepo:     permissionRepo,
		rolePermissionRepo: rolePermissionRepo,
	}
}

// Tenant
func (u *AuthorUsecase) CreateTenant(ctx context.Context, source *entities.Tenant) (*entities.Tenant, errors.BaseError) {
	return u.tenantRepo.Create(source)
}

func (u *AuthorUsecase) UpdateTenant(ctx context.Context, source *entities.Tenant) (*entities.Tenant, errors.BaseError) {
	return u.tenantRepo.Update(source)
}

func (u *AuthorUsecase) DeleteTenant(ctx context.Context, id string) errors.BaseError {
	return u.tenantRepo.Delete(id)
}

func (u *AuthorUsecase) GetTenant(ctx context.Context, id string) (*entities.Tenant, errors.BaseError) {
	return u.tenantRepo.Get(id)
}

func (u *AuthorUsecase) ListTenant(ctx context.Context, pagination *entities.Pagination) ([]*entities.Tenant, *entities.Pagination, errors.BaseError) {
	return u.tenantRepo.List(pagination)
}

// Role
func (u *AuthorUsecase) CreateRole(ctx context.Context, source *entities.Role) (*entities.Role, errors.BaseError) {
	return u.roleRepo.Create(source)
}

func (u *AuthorUsecase) UpdateRole(ctx context.Context, source *entities.Role) (*entities.Role, errors.BaseError) {
	return u.roleRepo.Update(source)
}

func (u *AuthorUsecase) DeleteRole(ctx context.Context, id string) errors.BaseError {
	return u.roleRepo.Delete(id)
}

func (u *AuthorUsecase) GetRole(ctx context.Context, id string) (*entities.Role, errors.BaseError) {
	return u.roleRepo.Get(id)
}

func (u *AuthorUsecase) ListRole(ctx context.Context, pagination *entities.Pagination) ([]*entities.Role, *entities.Pagination, errors.BaseError) {
	return u.roleRepo.List(pagination)
}

// Permission
func (u *AuthorUsecase) CreatePermission(ctx context.Context, source *entities.Permission) (*entities.Permission, errors.BaseError) {
	return u.permissionRepo.Create(source)
}

func (u *AuthorUsecase) UpdatePermission(ctx context.Context, source *entities.Permission) (*entities.Permission, errors.BaseError) {
	return u.permissionRepo.Update(source)
}

func (u *AuthorUsecase) DeletePermission(ctx context.Context, id string) errors.BaseError {
	return u.permissionRepo.Delete(id)
}

func (u *AuthorUsecase) GetPermission(ctx context.Context, id string) (*entities.Permission, errors.BaseError) {
	return u.permissionRepo.Get(id)
}

func (u *AuthorUsecase) ListPermission(ctx context.Context, pagination *entities.Pagination) ([]*entities.Permission, *entities.Pagination, errors.BaseError) {
	return u.permissionRepo.List(pagination)
}

func (u *AuthorUsecase) AssignPermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError) {
	return u.rolePermissionRepo.Assign(source)
}

func (u *AuthorUsecase) UnassignPermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError) {
	return u.rolePermissionRepo.Unassign(source)
}

func (u *AuthorUsecase) OverridePermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError) {
	return u.rolePermissionRepo.Override(source)
}

func (u *AuthorUsecase) Filter(ctx context.Context, source *entities.FilterPayload) (*entities.FilterResponse, errors.BaseError) {
	return nil, nil
}