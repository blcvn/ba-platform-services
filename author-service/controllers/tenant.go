package controllers

import (
	"context"
	"fmt"

	"github.com/blcvn/backend/services/author-service/common/constants"
	"github.com/blcvn/backend/services/author-service/common/errors"
	pb "github.com/blcvn/kratos-proto/go/author"
)

type authorizationController struct {
	pb.UnimplementedAuthorizationServiceServer
	utilities iUtilities
	transform iTransform
	validator iValidator
	usecase   iUsecase
}

func NewAuthorizationController(
	utilities iUtilities,
	transform iTransform,
	validator iValidator,
	usecase iUsecase,
) pb.AuthorizationServiceServer {
	return &authorizationController{
		utilities: utilities,
		transform: transform,
		validator: validator,
		usecase:   usecase,
	}
}

func (c *authorizationController) CreateTenant(ctx context.Context, req *pb.TenantRequest) (*pb.TenantResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelTenantPayload(req.Payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformTenantRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidateTenant(payload); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateTenantError, err.Error()), nil), nil
	}

	result, err := c.usecase.CreateTenant(ctx, payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode(err.GetCode()), fmt.Sprintf(constants.MsgCreateTenantError, err.Error()), nil), nil
	}

	pbTenant, err := c.transform.Model2PbTenant(result)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformTenantError, err.Error()), nil), nil
	}

	return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgCreateTenantSuccess, pbTenant), nil
}

func (c *authorizationController) UpdateTenant(ctx context.Context, req *pb.TenantRequest) (*pb.TenantResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelTenantPayload(req.Payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformTenantRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidateTenant(payload); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateTenantError, err.Error()), nil), nil
	}

	result, err := c.usecase.UpdateTenant(ctx, payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode(err.GetCode()), fmt.Sprintf(constants.MsgUpdateTenantError, err.Error()), nil), nil
	}

	pbTenant, err := c.transform.Model2PbTenant(result)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformTenantError, err.Error()), nil), nil
	}

	return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgUpdateTenantSuccess, pbTenant), nil
}

func (c *authorizationController) DeleteTenant(ctx context.Context, req *pb.TenantRequest) (*pb.TenantResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelTenantPayload(req.Payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformTenantRequestError, err.Error()), nil), nil
	}

	if err := c.usecase.DeleteTenant(ctx, payload.Id); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode(err.GetCode()), fmt.Sprintf(constants.MsgDeleteTenantError, err.Error()), nil), nil
	}

	return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgDeleteTenantSuccess, nil), nil
}

func (c *authorizationController) GetTenant(ctx context.Context, req *pb.TenantRequest) (*pb.TenantResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelTenantPayload(req.Payload)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformTenantRequestError, err.Error()), nil), nil
	}

	result, err := c.usecase.GetTenant(ctx, payload.Id)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode(err.GetCode()), fmt.Sprintf(constants.MsgGetTenantError, err.Error()), nil), nil
	}

	pbTenant, err := c.transform.Model2PbTenant(result)
	if err != nil {
		return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformTenantError, err.Error()), nil), nil
	}

	return buildTenantResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgGetTenantSuccess, pbTenant), nil
}

func (c *authorizationController) ListTenant(ctx context.Context, req *pb.ListTenantRequest) (*pb.ListTenantResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.ListTenantResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}
	pagination, err := c.transform.Pb2ModelPagination(req.GetPagination())
	if err != nil {
		return &pb.ListTenantResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}

	tenants, _pagination, err := c.usecase.ListTenant(ctx, pagination)
	if err != nil {
		return &pb.ListTenantResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgListTenantError, err.Error())},
		}, nil
	}
	paginationPb, err := c.transform.Model2PbPagination(_pagination)
	if err != nil {
		return &pb.ListTenantResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformPaginationError, err.Error())},
		}, nil
	}
	tenantPb2, err := c.transform.Model2PbListTenant(tenants)
	if err != nil {
		return &pb.ListTenantResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformTenantError, err.Error())},
		}, nil
	}

	return &pb.ListTenantResponse{
		Metadata:   req.Metadata,
		Signature:  req.Signature,
		Pagination: paginationPb,
		Payload:    tenantPb2,
		Result:     &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgListTenantSuccess},
	}, nil
}

func (c *authorizationController) CreateRole(ctx context.Context, req *pb.RoleRequest) (*pb.RoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelRolePayload(req.Payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRoleRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidateRole(payload); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRoleError, err.Error()), nil), nil
	}

	result, err := c.usecase.CreateRole(ctx, payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgCreateRoleError, err.Error()), nil), nil
	}

	pbRole, err := c.transform.Model2PbRole(result)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRoleError, err.Error()), nil), nil
	}

	return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgCreateRoleSuccess, pbRole), nil
}

func (c *authorizationController) UpdateRole(ctx context.Context, req *pb.RoleRequest) (*pb.RoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelRolePayload(req.Payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRoleRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidateRole(payload); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRoleError, err.Error()), nil), nil
	}

	result, err := c.usecase.UpdateRole(ctx, payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgUpdateRoleError, err.Error()), nil), nil
	}

	pbRole, err := c.transform.Model2PbRole(result)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRoleError, err.Error()), nil), nil
	}

	return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgUpdateRoleSuccess, pbRole), nil
}

func (c *authorizationController) DeleteRole(ctx context.Context, req *pb.RoleRequest) (*pb.RoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelRolePayload(req.Payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRoleRequestError, err.Error()), nil), nil
	}

	if err := c.usecase.DeleteRole(ctx, payload.Id); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgDeleteRoleError, err.Error()), nil), nil
	}

	return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgDeleteRoleSuccess, nil), nil
}

func (c *authorizationController) GetRole(ctx context.Context, req *pb.RoleRequest) (*pb.RoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelRolePayload(req.Payload)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRoleRequestError, err.Error()), nil), nil
	}

	result, err := c.usecase.GetRole(ctx, payload.Id)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgGetRoleError, err.Error()), nil), nil
	}

	pbRole, err := c.transform.Model2PbRole(result)
	if err != nil {
		return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRoleError, err.Error()), nil), nil
	}

	return buildRoleResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgGetRoleSuccess, pbRole), nil
}

func (c *authorizationController) ListRole(ctx context.Context, req *pb.ListRoleRequest) (*pb.ListRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.ListRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}

	pagination, err := c.transform.Pb2ModelPagination(req.Pagination)
	if err != nil {
		return &pb.ListRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}

	roles, _pagination, err := c.usecase.ListRole(ctx, pagination)
	if err != nil {
		return &pb.ListRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgListRoleError, err.Error())},
		}, nil
	}

	paginationPb, err := c.transform.Model2PbPagination(_pagination)
	if err != nil {
		return &pb.ListRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformPaginationError, err.Error())},
		}, nil
	}

	rolePb2, err := c.transform.Model2PbListRole(roles)
	if err != nil {
		return &pb.ListRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformRoleError, err.Error())},
		}, nil
	}

	return &pb.ListRoleResponse{
		Metadata:   req.Metadata,
		Signature:  req.Signature,
		Pagination: paginationPb,
		Payload:    rolePb2,
		Result:     &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgListRoleSuccess},
	}, nil
}

func (c *authorizationController) CreatePermission(ctx context.Context, req *pb.PermissionRequest) (*pb.PermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelPermissionPayload(req.Payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformPermissionRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidatePermission(payload); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidatePermissionError, err.Error()), nil), nil
	}

	result, err := c.usecase.CreatePermission(ctx, payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgCreatePermissionError, err.Error()), nil), nil
	}

	pbPermission, err := c.transform.Model2PbPermission(result)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformPermissionError, err.Error()), nil), nil
	}

	return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgCreatePermissionSuccess, pbPermission), nil
}

func (c *authorizationController) UpdatePermission(ctx context.Context, req *pb.PermissionRequest) (*pb.PermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelPermissionPayload(req.Payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformPermissionRequestError, err.Error()), nil), nil
	}

	if err := c.validator.ValidatePermission(payload); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidatePermissionError, err.Error()), nil), nil
	}

	result, err := c.usecase.UpdatePermission(ctx, payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgUpdatePermissionError, err.Error()), nil), nil
	}

	pbPermission, err := c.transform.Model2PbPermission(result)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformPermissionError, err.Error()), nil), nil
	}

	return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgUpdatePermissionSuccess, pbPermission), nil
}

func (c *authorizationController) DeletePermission(ctx context.Context, req *pb.PermissionRequest) (*pb.PermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelPermissionPayload(req.Payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformPermissionRequestError, err.Error()), nil), nil
	}

	if err := c.usecase.DeletePermission(ctx, payload.Id); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgDeletePermissionError, err.Error()), nil), nil
	}

	return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgDeletePermissionSuccess, nil), nil
}

func (c *authorizationController) GetPermission(ctx context.Context, req *pb.PermissionRequest) (*pb.PermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error()), nil), nil
	}

	payload, err := c.transform.Pb2ModelPermissionPayload(req.Payload)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformPermissionRequestError, err.Error()), nil), nil
	}

	result, err := c.usecase.GetPermission(ctx, payload.Id)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgGetPermissionError, err.Error()), nil), nil
	}

	pbPermission, err := c.transform.Model2PbPermission(result)
	if err != nil {
		return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformPermissionError, err.Error()), nil), nil
	}

	return buildPermissionResponse(req.Metadata, req.Signature, pb.ResultCode_SUCCESS, constants.MsgGetPermissionSuccess, pbPermission), nil
}

func (c *authorizationController) ListPermission(ctx context.Context, req *pb.ListPermissionRequest) (*pb.ListPermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.ListPermissionResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}

	pagination, err := c.transform.Pb2ModelPagination(req.Pagination)
	if err != nil {
		return &pb.ListPermissionResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_BAD_REQUEST, Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error())},
		}, nil
	}

	permissions, _pagination, err := c.usecase.ListPermission(ctx, pagination)
	if err != nil {
		return &pb.ListPermissionResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgListPermissionError, err.Error())},
		}, nil
	}

	paginationPb, err := c.transform.Model2PbPagination(_pagination)
	if err != nil {
		return &pb.ListPermissionResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformPaginationError, err.Error())},
		}, nil
	}

	permissionsPb, err := c.transform.Model2PbListPermission(permissions)
	if err != nil {
		return &pb.ListPermissionResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result:    &pb.Result{Code: pb.ResultCode_INTERNAL, Message: fmt.Sprintf(constants.MsgTransformPermissionError, err.Error())},
		}, nil
	}

	return &pb.ListPermissionResponse{
		Metadata:   req.Metadata,
		Signature:  req.Signature,
		Pagination: paginationPb,
		Payload:    permissionsPb,
		Result:     &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgListPermissionSuccess},
	}, nil
}

func (c *authorizationController) AssignPermission(ctx context.Context, req *pb.RolePermissionRequest) (*pb.RolePermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error())), nil
	}

	payload, err := c.transform.Pb2ModelRolePermissionPayload(req.Payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRolePermissionRequestError, err.Error())), nil
	}

	if err := c.validator.ValidateRolePermission(payload); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRolePermissionError, err.Error())), nil
	}

	result, err := c.usecase.AssignPermission(ctx, payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgAssignPermissionError, err.Error())), nil
	}

	response, err := c.transform.Model2PbRolePermission(result)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRolePermissionError, err.Error())), nil
	}

	response.Result = &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgAssignPermissionSuccess}
	return response, nil
}

func (c *authorizationController) UnassignPermission(ctx context.Context, req *pb.RolePermissionRequest) (*pb.RolePermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error())), nil
	}

	payload, err := c.transform.Pb2ModelRolePermissionPayload(req.Payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRolePermissionRequestError, err.Error())), nil
	}

	if err := c.validator.ValidateRolePermission(payload); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRolePermissionError, err.Error())), nil
	}

	result, err := c.usecase.UnassignPermission(ctx, payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgUnassignPermissionError, err.Error())), nil
	}

	response, err := c.transform.Model2PbRolePermission(result)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRolePermissionError, err.Error())), nil
	}

	response.Result = &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgUnassignPermissionSuccess}
	return response, nil
}

func (c *authorizationController) OverridePermission(ctx context.Context, req *pb.RolePermissionRequest) (*pb.RolePermissionResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRequestError, err.Error())), nil
	}

	payload, err := c.transform.Pb2ModelRolePermissionPayload(req.Payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgTransformRolePermissionRequestError, err.Error())), nil
	}

	if err := c.validator.ValidateRolePermission(payload); err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_BAD_REQUEST, fmt.Sprintf(constants.MsgValidateRolePermissionError, err.Error())), nil
	}

	result, err := c.usecase.OverridePermission(ctx, payload)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgOverridePermissionError, err.Error())), nil
	}

	response, err := c.transform.Model2PbRolePermission(result)
	if err != nil {
		return buildRolePermissionResponse(req.Metadata, req.Signature, pb.ResultCode_INTERNAL, fmt.Sprintf(constants.MsgTransformRolePermissionError, err.Error())), nil
	}

	response.Result = &pb.Result{Code: pb.ResultCode_SUCCESS, Message: constants.MsgOverridePermissionSuccess}
	return response, nil
}

// Internal Helpers

func (c *authorizationController) validateRequest(ctx context.Context, metadata *pb.Metadata, signature *pb.Signature) errors.BaseError {
	_metadata, err := c.transform.Pb2ModelMetadata(metadata)
	if err != nil {
		return err
	}
	_signature, err := c.transform.Pb2ModelSignature(signature)
	if err != nil {
		return err
	}
	if err := c.validator.ValidateMetadata(_metadata); err != nil {
		return err
	}
	if err := c.validator.ValidateSignature(_signature); err != nil {
		return err
	}
	return nil
}
