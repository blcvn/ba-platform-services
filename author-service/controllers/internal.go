package controllers

import (
	"context"

	"github.com/blcvn/backend/services/author-service/common/errors"
	"github.com/blcvn/backend/services/author-service/entities"
	pb "github.com/blcvn/kratos-proto/go/author"
)

type iUtilities interface {
	GetHeaderKey(ctx context.Context, key string) string
	GetHeaderListString(ctx context.Context, key string) []string
	GetQueryParam(ctx context.Context, key string) string
}

type iTransform interface {
	Pb2ModelMetadata(source *pb.Metadata) (*entities.Metadata, errors.BaseError)
	Pb2ModelSignature(source *pb.Signature) (*entities.Signature, errors.BaseError)
	Pb2ModelPagination(source *pb.Pagination) (*entities.Pagination, errors.BaseError)

	Pb2ModelTenantPayload(source *pb.TenantPayload) (*entities.Tenant, errors.BaseError)
	Pb2ModelRolePayload(source *pb.RolePayload) (*entities.Role, errors.BaseError)
	Pb2ModelPermissionPayload(source *pb.PermissionPayload) (*entities.Permission, errors.BaseError)
	Pb2ModelRolePermissionPayload(source *pb.RolePermissionPayload) (*entities.RolePermission, errors.BaseError)

	// List requests
	Pb2ModelFilterPayload(source *pb.FilterPayload) (*entities.FilterPayload, errors.BaseError)

	// To Pb
	Model2PbTenant(source *entities.Tenant) (*pb.TenantPayload, errors.BaseError)
	Model2PbListTenant(source []*entities.Tenant) ([]*pb.TenantPayload, errors.BaseError)

	Model2PbRole(source *entities.Role) (*pb.RolePayload, errors.BaseError)
	Model2PbListRole(source []*entities.Role) ([]*pb.RolePayload, errors.BaseError)

	Model2PbPermission(source *entities.Permission) (*pb.PermissionPayload, errors.BaseError)
	Model2PbListPermission(source []*entities.Permission) ([]*pb.PermissionPayload, errors.BaseError)

	Model2PbRolePermission(source *entities.RolePermission) (*pb.RolePermissionResponse, errors.BaseError)
	Model2PbPagination(source *entities.Pagination) (*pb.Pagination, errors.BaseError)
}

type iValidator interface {
	ValidateMetadata(source *entities.Metadata) errors.BaseError
	ValidateSignature(source *entities.Signature) errors.BaseError

	ValidateTenant(source *entities.Tenant) errors.BaseError
	ValidateRole(source *entities.Role) errors.BaseError
	ValidatePermission(source *entities.Permission) errors.BaseError
	ValidateRolePermission(source *entities.RolePermission) errors.BaseError
}

type iUsecase interface {
	CreateTenant(ctx context.Context, source *entities.Tenant) (*entities.Tenant, errors.BaseError)
	UpdateTenant(ctx context.Context, source *entities.Tenant) (*entities.Tenant, errors.BaseError)
	DeleteTenant(ctx context.Context, id string) errors.BaseError
	GetTenant(ctx context.Context, id string) (*entities.Tenant, errors.BaseError)
	ListTenant(ctx context.Context, pagination *entities.Pagination) ([]*entities.Tenant, *entities.Pagination, errors.BaseError)

	CreateRole(ctx context.Context, source *entities.Role) (*entities.Role, errors.BaseError)
	UpdateRole(ctx context.Context, source *entities.Role) (*entities.Role, errors.BaseError)
	DeleteRole(ctx context.Context, id string) errors.BaseError
	GetRole(ctx context.Context, id string) (*entities.Role, errors.BaseError)
	ListRole(ctx context.Context, pagination *entities.Pagination) ([]*entities.Role, *entities.Pagination, errors.BaseError)

	CreatePermission(ctx context.Context, source *entities.Permission) (*entities.Permission, errors.BaseError)
	UpdatePermission(ctx context.Context, source *entities.Permission) (*entities.Permission, errors.BaseError)
	DeletePermission(ctx context.Context, id string) errors.BaseError
	GetPermission(ctx context.Context, id string) (*entities.Permission, errors.BaseError)
	ListPermission(ctx context.Context, pagination *entities.Pagination) ([]*entities.Permission, *entities.Pagination, errors.BaseError)

	AssignPermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError)
	UnassignPermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError)
	OverridePermission(ctx context.Context, source *entities.RolePermission) (*entities.RolePermission, errors.BaseError)

	Filter(ctx context.Context, source *entities.FilterPayload) (*entities.FilterResponse, errors.BaseError)
}
