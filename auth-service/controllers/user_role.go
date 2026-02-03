package controllers

import (
	"context"
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	pb "github.com/blcvn/kratos-proto/go/authen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userRoleController struct {
	pb.UnimplementedUserRoleServiceServer
	utilities iUtilities
	transform iTransform
	validator iValidator
	usecase   iRoleUsecase
}

func (c *userRoleController) AssignRole(ctx context.Context, req *pb.UserRoleRequest) (*pb.UserRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	rolePayload, err := c.transform.Pb2ModelRolePayload(req.GetPayload())
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformRolePayloadError, err.Error()),
			},
		}, nil
	}
	tenantId := c.utilities.GetHeaderKey(ctx, "X-Tenant-ID")
	roleIds := c.utilities.GetHeaderListString(ctx, "X-Roles")
	if err := c.validator.ValidateRoles(tenantId, roleIds, rolePayload); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRoleError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.usecase.AssignRoles(rolePayload)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgAssignRoleError, err.Error()),
			},
		}, nil
	}
	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.UserRoleResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgAssignRoleSuccess,
		},
		User: userInfoPb,
	}, nil
}

func (c *userRoleController) UnassignRole(ctx context.Context, req *pb.UserRoleRequest) (*pb.UserRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	rolePayload, err := c.transform.Pb2ModelRolePayload(req.GetPayload())
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformRolePayloadError, err.Error()),
			},
		}, nil
	}
	tenantId := c.utilities.GetHeaderKey(ctx, "X-Tenant-ID")
	roleIds := c.utilities.GetHeaderListString(ctx, "X-Roles")
	if err := c.validator.ValidateRoles(tenantId, roleIds, rolePayload); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRoleError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.usecase.UnassignRoles(rolePayload)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgUnassignRoleError, err.Error()),
			},
		}, nil
	}
	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.UserRoleResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgUnassignRoleSuccess,
		},
		User: userInfoPb,
	}, nil
}

func (c *userRoleController) OverrideRole(ctx context.Context, req *pb.UserRoleRequest) (*pb.UserRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	rolePayload, err := c.transform.Pb2ModelRolePayload(req.GetPayload())
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformRolePayloadError, err.Error()),
			},
		}, nil
	}
	tenantId := c.utilities.GetHeaderKey(ctx, "X-Tenant-ID")
	roleIds := c.utilities.GetHeaderListString(ctx, "X-Roles")
	if err := c.validator.ValidateRoles(tenantId, roleIds, rolePayload); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRoleError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.usecase.OverrideRoles(rolePayload)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgOverrideRoleError, err.Error()),
			},
		}, nil
	}
	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.UserRoleResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgOverrideRoleSuccess,
		},
		User: userInfoPb,
	}, nil
}

func (c *userRoleController) ListRole(ctx context.Context, req *pb.SearchRequest) (*pb.ListUserRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListRole not implemented")
}

func (c *userRoleController) ActiveUser(ctx context.Context, req *pb.UserStatusRequest) (*pb.UserRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}

	payload, err := c.transform.Pb2ModelUserStatusPayload(req.GetPayload())
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: err.Error(),
			},
		}, nil
	}

	tenantId := c.utilities.GetHeaderKey(ctx, "X-Tenant-ID")
	roleIds := c.utilities.GetHeaderListString(ctx, "X-Roles")

	if err := c.validator.ValidateUser(tenantId, roleIds, payload); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRoleError, err.Error()),
			},
		}, nil
	}

	userInfo, err := c.usecase.ActiveUser(payload.TenantId, payload.UserId)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgActiveUserError, err.Error()),
			},
		}, nil
	}

	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}

	return &pb.UserRoleResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgActiveUserSuccess,
		},
		User: userInfoPb,
	}, nil
}

func (c *userRoleController) InactiveUser(ctx context.Context, req *pb.UserStatusRequest) (*pb.UserRoleResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}

	payload, err := c.transform.Pb2ModelUserStatusPayload(req.GetPayload())
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: err.Error(),
			},
		}, nil
	}

	tenantId := c.utilities.GetHeaderKey(ctx, "X-Tenant-ID")
	roleIds := c.utilities.GetHeaderListString(ctx, "X-Roles")
	if err := c.validator.ValidateUser(tenantId, roleIds, payload); err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRoleError, err.Error()),
			},
		}, nil
	}

	userInfo, err := c.usecase.InactiveUser(payload.TenantId, payload.UserId)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgInactiveUserError, err.Error()),
			},
		}, nil
	}

	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.UserRoleResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}

	return &pb.UserRoleResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgInactiveUserSuccess,
		},
		User: userInfoPb,
	}, nil
}

// internal function
func (c *userRoleController) validateRequest(ctx context.Context, metadata *pb.Metadata, signature *pb.Signature) errors.BaseError {
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
