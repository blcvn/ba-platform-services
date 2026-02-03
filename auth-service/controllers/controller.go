package controllers

import (
	"context"
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/configs"
	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	pb "github.com/blcvn/kratos-proto/go/authen"
)

type authenController struct {
	pb.UnimplementedAuthenticateServiceServer
	utilities iUtilities
	transform iTransform
	validator iValidator
	usecase   iAuthUsecase
}

// Register with username/password
func (c *authenController) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.RegisterResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	registerPayload, err := c.transform.Pb2ModelRegisterPayload(req.GetPayload())
	if err != nil {
		return &pb.RegisterResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformRegisterPayloadError, err.Error()),
			},
		}, nil
	}
	if err := c.validator.ValidateRegister(registerPayload); err != nil {
		return &pb.RegisterResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRegisterError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.usecase.Register(ctx, registerPayload)
	if err != nil {
		return &pb.RegisterResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgRegisterError, err.Error()),
			},
		}, nil
	}
	userInfoPb, err := c.transform.Model2PbUserInfo(userInfo)
	if err != nil {
		return &pb.RegisterResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.RegisterResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgRegisterSuccess,
		},
		User: userInfoPb,
	}, nil
}

// Login with username/password
func (c *authenController) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	loginPayload, err := c.transform.Pb2ModelLoginPayload(req.GetPayload())
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformLoginPayloadError, err.Error()),
			},
		}, nil
	}
	if err := c.validator.ValidateLogin(loginPayload); err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateLoginError, err.Error()),
			},
		}, nil
	}
	userData, err := c.usecase.Login(ctx, loginPayload)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgLoginError, err.Error()),
			},
		}, nil
	}
	token, err := c.transform.Model2PbToken(userData.Token)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformTokenError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.transform.Model2PbUserInfo(userData.UserInfo)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.LoginResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgLoginSuccess,
		},
		Token: token,
		User:  userInfo,
	}, nil
}

// Login with Google OAuth2
func (c *authenController) LoginWithGoogle(ctx context.Context, req *pb.LoginWithGoogleRequest) (*pb.LoginResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	tenantId := c.utilities.GetQueryParam(ctx, "tenant_id")
	loginPayload, err := c.transform.Pb2ModelLoginWithGooglePayload(req.GetPayload())
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgTransformLoginPayloadError, err.Error()),
			},
		}, nil
	}
	loginPayload.TenantId = tenantId
	if err := c.validator.ValidateLogin(loginPayload); err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateLoginError, err.Error()),
			},
		}, nil
	}
	userData, err := c.usecase.LoginWithGoogle(ctx, loginPayload)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgLoginError, err.Error()),
			},
		}, nil
	}
	token, err := c.transform.Model2PbToken(userData.Token)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformTokenError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.transform.Model2PbUserInfo(userData.UserInfo)
	if err != nil {
		return &pb.LoginResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.LoginResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgLoginSuccess,
		},
		Token: token,
		User:  userInfo,
	}, nil
}

// Logout (revoke refresh token / session)
func (c *authenController) Logout(ctx context.Context, req *pb.AuthenticationRequest) (*pb.AuthenticationResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.AuthenticationResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	accessToken := c.utilities.GetHeaderKey(ctx, "Authorization")
	userSession, err := c.usecase.VerifyToken(accessToken)
	if err != nil {
		return &pb.AuthenticationResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_UNAUTHORIZED,
				Message: fmt.Sprintf(constants.MsgVerifyTokenError, err.Error()),
			},
		}, nil
	}

	err = c.usecase.Logout(ctx, accessToken, userSession)
	if err != nil {
		return &pb.AuthenticationResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgLogoutError, err.Error()),
			},
		}, nil
	}
	return &pb.AuthenticationResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgLogoutSuccess,
		},
	}, nil
}

// Verify access token (used by Kong / internal services)
func (c *authenController) VerifyToken(ctx context.Context, req *pb.AuthenticationRequest) (*pb.TokenResponse, error) {
	accessToken := c.utilities.GetHeaderKey(ctx, "Authorization")
	userSession, err := c.usecase.VerifyToken(accessToken)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgVerifyTokenError, err.Error()),
			},
		}, nil
	}

	// Set response headers for Kong gateway
	// X-User-ID: identity
	c.utilities.SetResponseHeader(ctx, configs.KongHeaderCfg.UserIDHeader, userSession.UserId)
	// X-Tenant-ID: tenant isolation
	c.utilities.SetResponseHeader(ctx, configs.KongHeaderCfg.TenantIDHeader, userSession.TenantId)
	// X-Roles: coarse-grained auth
	c.utilities.SetResponseHeaders(ctx, configs.KongHeaderCfg.RolesHeader, userSession.RoleIds)

	return &pb.TokenResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgVerifyTokenSuccess,
		},
		User: &pb.UserInfo{
			UserId:   userSession.UserId,
			TenantId: userSession.TenantId,
			Roles:    userSession.RoleIds,
		},
	}, nil
}

// Renew access token using refresh token
func (c *authenController) RenewAccessToken(ctx context.Context, req *pb.AuthenticationRequest) (*pb.TokenResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	accessToken := c.utilities.GetHeaderKey(ctx, "Authorization")
	refreshToken := c.utilities.GetHeaderKey(ctx, "RefreshToken")
	userData, err := c.usecase.RenewAccessToken(ctx, accessToken, refreshToken)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgRenewTokenError, err.Error()),
			},
		}, nil
	}
	token, err := c.transform.Model2PbToken(userData.Token)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformTokenError, err.Error()),
			},
		}, nil
	}
	userInfo, err := c.transform.Model2PbUserInfo(userData.UserInfo)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_INTERNAL,
				Message: fmt.Sprintf(constants.MsgTransformUserInfoError, err.Error()),
			},
		}, nil
	}
	return &pb.TokenResponse{
		Metadata:  req.Metadata,
		Signature: req.Signature,
		Result: &pb.Result{
			Code:    pb.ResultCode_SUCCESS,
			Message: constants.MsgRenewTokenSuccess,
		},
		Token: token,
		User:  userInfo,
	}, nil
}

func (c *authenController) RevokeAccessToken(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.TokenResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	if req.Token == nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: "Token is required",
			},
		}, nil
	}
	accessToken := req.Token.AccessToken
	err := c.usecase.RevokeAccessToken(ctx, accessToken)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgRenewAccessTokenError, err.Error()),
			},
		}, nil
	} else {

		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_SUCCESS,
				Message: constants.MsgRevokeAccessTokenSuccess,
			},
		}, nil
	}
}

func (c *authenController) RevokeRefreshToken(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.TokenResponse, error) {
	if err := c.validateRequest(ctx, req.GetMetadata(), req.GetSignature()); err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: fmt.Sprintf(constants.MsgValidateRequestError, err.Error()),
			},
		}, nil
	}
	if req.Token == nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_BAD_REQUEST,
				Message: "Token is required",
			},
		}, nil
	}
	accessToken := req.Token.AccessToken
	refreshToken := req.Token.RefreshToken
	err := c.usecase.RevokeRefreshToken(ctx, accessToken, refreshToken)
	if err != nil {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode(err.GetCode()),
				Message: fmt.Sprintf(constants.MsgRevokeRefreshTokenError, err.Error()),
			},
		}, nil
	} else {
		return &pb.TokenResponse{
			Metadata:  req.Metadata,
			Signature: req.Signature,
			Result: &pb.Result{
				Code:    pb.ResultCode_SUCCESS,
				Message: constants.MsgRevokeRefreshTokenSuccess,
			},
		}, nil
	}
}

// internal function
func (c *authenController) validateRequest(ctx context.Context, metadata *pb.Metadata, signature *pb.Signature) errors.BaseError {
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
