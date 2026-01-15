package helper

import (
	"fmt"

	pb "github.com/anhdt/erp-protos/go/author"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/common/errors"
	"github.com/anhdt/golang-enterprise-repo/services/author-service/entities"
)

type transform struct{}

func NewTransform() *transform {
	return &transform{}
}

func (t *transform) Pb2ModelMetadata(source *pb.Metadata) (*entities.Metadata, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &entities.Metadata{
		RequestId:   source.RequestId,
		RequestTime: source.RequestTime,
		Version:     source.Version,
	}, nil
}

func (t *transform) Pb2ModelSignature(source *pb.Signature) (*entities.Signature, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &entities.Signature{
		Type: entities.SignatureType(source.SType),
		S:    source.S,
		B:    source.B,
	}, nil
}

func (t *transform) Pb2ModelPagination(source *pb.Pagination) (*entities.Pagination, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &entities.Pagination{
		Page:  int64(source.Page),
		Limit: int64(source.Limit),
		Total: int64(source.Total),
	}, nil
}

// To Model
func (t *transform) Pb2ModelTenantPayload(source *pb.TenantPayload) (*entities.Tenant, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(400, fmt.Errorf("invalid payload"))
	}
	// TODO: Map fields
	return &entities.Tenant{
		Name:        source.Name,
		Description: source.Description,
		Id:          source.TenantId,
		CreatedAt:   source.CreatedAt,
		UpdatedAt:   source.UpdatedAt,
	}, nil
}

func (t *transform) Pb2ModelRolePayload(source *pb.RolePayload) (*entities.Role, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(400, fmt.Errorf("invalid payload"))
	}
	return &entities.Role{
		Name:        source.Name,
		Description: source.Description,
		TenantId:    source.TenantId,
		Id:          source.RoleId,
		Status:      int(source.Status),
		CreatedAt:   source.CreatedAt,
		UpdatedAt:   source.UpdatedAt,
	}, nil
}

func (t *transform) Pb2ModelPermissionPayload(source *pb.PermissionPayload) (*entities.Permission, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(400, fmt.Errorf("invalid payload"))
	}
	return &entities.Permission{
		Name:        source.Name,
		Description: source.Description,
		TenantId:    source.TenantId,
		Id:          source.PermissionId,
		Status:      int(source.Status),
		CreatedAt:   source.CreatedAt,
		UpdatedAt:   source.UpdatedAt,
	}, nil
}

func (t *transform) Pb2ModelRolePermissionPayload(source *pb.RolePermissionPayload) (*entities.RolePermission, errors.BaseError) {
	if source == nil || source.RoleId == "" || source.Permissions == nil {
		return nil, errors.NewBaseError(400, fmt.Errorf("invalid payload"))
	}
	return &entities.RolePermission{
		RoleId:        source.RoleId,
		PermissionIds: append([]string{}, source.Permissions...),
	}, nil
}

func (t *transform) Pb2ModelFilterPayload(source *pb.FilterPayload) (*entities.FilterPayload, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(400, fmt.Errorf("invalid payload"))
	}
	return &entities.FilterPayload{
		TenantId:     source.TenantId,
		RoleId:       source.RoleId,
		PermissionId: source.PermissionId,
	}, nil
}

// To Pb
func (t *transform) Model2PbTenant(source *entities.Tenant) (*pb.TenantPayload, errors.BaseError) {
	// TODO: map
	return &pb.TenantPayload{
		TenantId:    source.Id,
		Name:        source.Name,
		Description: source.Description,
	}, nil
}

func (t *transform) Model2PbListTenant(source []*entities.Tenant) ([]*pb.TenantPayload, errors.BaseError) {
	list := make([]*pb.TenantPayload, len(source))
	for i, item := range source {
		list[i] = &pb.TenantPayload{
			TenantId:    item.Id,
			Name:        item.Name,
			Description: item.Description,
		}
	}
	return list, nil
}

func (t *transform) Model2PbRole(source *entities.Role) (*pb.RolePayload, errors.BaseError) {
	return &pb.RolePayload{
		RoleId:      source.Id,
		TenantId:    source.TenantId,
		Name:        source.Name,
		Description: source.Description,
	}, nil
}

func (t *transform) Model2PbListRole(source []*entities.Role) ([]*pb.RolePayload, errors.BaseError) {
	list := make([]*pb.RolePayload, len(source))
	for i, item := range source {
		list[i] = &pb.RolePayload{
			RoleId:      item.Id,
			TenantId:    item.TenantId,
			Name:        item.Name,
			Description: item.Description,
		}
	}
	return list, nil
}

func (t *transform) Model2PbPermission(source *entities.Permission) (*pb.PermissionPayload, errors.BaseError) {
	return &pb.PermissionPayload{
		PermissionId: source.Id,
		TenantId:     source.TenantId,
		Name:         source.Name,
		Description:  source.Description,
	}, nil
}

func (t *transform) Model2PbListPermission(source []*entities.Permission) ([]*pb.PermissionPayload, errors.BaseError) {
	list := make([]*pb.PermissionPayload, len(source))
	for i, item := range source {
		list[i] = &pb.PermissionPayload{
			PermissionId: item.Id,
			TenantId:     item.TenantId,
			Name:         item.Name,
			Description:  item.Description,
		}
	}
	return list, nil
}

func (t *transform) Model2PbRolePermission(source *entities.RolePermission) (*pb.RolePermissionResponse, errors.BaseError) {
	permissions := make([]*pb.PermissionPayload, len(source.PermissionIds))
	for i, id := range source.PermissionIds {
		permissions[i] = &pb.PermissionPayload{
			PermissionId: id,
		}
	}

	return &pb.RolePermissionResponse{
		Payload: &pb.RolePermissionData{
			Role: &pb.RolePayload{
				RoleId: source.RoleId,
			},
			Permissions: permissions,
		},
	}, nil
}

func (t *transform) Model2PbFilterResponse(source *entities.FilterResponse) (*pb.FilterResponse, errors.BaseError) {
	code := pb.ResultCode_SUCCESS
	if !source.Allowed {
		code = pb.ResultCode_FORBIDDEN
	}
	return &pb.FilterResponse{
		Result: &pb.Result{
			Code:    code,
			Message: source.Reason,
		},
	}, nil
}

func (t *transform) Model2PbPagination(source *entities.Pagination) (*pb.Pagination, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &pb.Pagination{
		Page:  source.Page,
		Limit: source.Limit,
		Total: source.Total,
	}, nil
}
