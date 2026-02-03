package controllers

import (
	"context"

	pb "github.com/blcvn/kratos-proto/go/authen"

	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/entities"
)

type iUtilities interface {
	GetHeaderKey(ctx context.Context, key string) string
	GetHeaderListString(ctx context.Context, key string) []string
	GetQueryParam(ctx context.Context, key string) string
	SetResponseHeader(ctx context.Context, key, value string) error
	SetResponseHeaders(ctx context.Context, key string, values []string) error
}

type iTransform interface {
	Pb2ModelMetadata(source *pb.Metadata) (*entities.Metadata, errors.BaseError)
	Pb2ModelSignature(source *pb.Signature) (*entities.Signature, errors.BaseError)
	Pb2ModelRegisterPayload(source *pb.RegisterPayload) (*entities.RegisterPayload, errors.BaseError)
	Pb2ModelLoginPayload(source *pb.LoginPayload) (*entities.LoginPayload, errors.BaseError)
	Pb2ModelLoginWithGooglePayload(source *pb.LoginWithGooglePayload) (*entities.LoginPayload, errors.BaseError)
	Pb2ModelRolePayload(source *pb.RolePayload) (*entities.RolePayload, errors.BaseError)
	Pb2ModelUserStatusPayload(source *pb.UserStatusPayload) (*entities.UserInfo, errors.BaseError)

	Model2PbMetadata(source *entities.Metadata) (*pb.Metadata, errors.BaseError)
	Model2PbSignature(source *entities.Signature) (*pb.Signature, errors.BaseError)
	Model2PbUserInfo(source *entities.UserInfo) (*pb.UserInfo, errors.BaseError)
	Model2PbToken(source *entities.Token) (*pb.TokenMessage, errors.BaseError)
}

type iValidator interface {
	ValidateMetadata(source *entities.Metadata) errors.BaseError
	ValidateSignature(source *entities.Signature) errors.BaseError
	ValidateRegister(source *entities.RegisterPayload) errors.BaseError
	ValidateLogin(source *entities.LoginPayload) errors.BaseError
	ValidateUser(tenantId string, roleIds []string, source *entities.UserInfo) errors.BaseError
	ValidateRoles(tenantId string, roleIds []string, source *entities.RolePayload) errors.BaseError
}

type iAuthUsecase interface {
	Register(ctx context.Context, source *entities.RegisterPayload) (*entities.UserInfo, errors.BaseError)
	Login(ctx context.Context, source *entities.LoginPayload) (*entities.UserData, errors.BaseError)
	LoginWithGoogle(ctx context.Context, source *entities.LoginPayload) (*entities.UserData, errors.BaseError)
	Logout(ctx context.Context, accessToken string, userSession *entities.UserSession) errors.BaseError
	RenewAccessToken(ctx context.Context, accessToken, refreshToken string) (*entities.UserData, errors.BaseError)
	RevokeAccessToken(ctx context.Context, accessToken string) errors.BaseError
	RevokeRefreshToken(ctx context.Context, accessToken, refreshToken string) errors.BaseError
	VerifyToken(accessToken string) (*entities.UserSession, errors.BaseError)
}

type iRoleUsecase interface {
	AssignRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError)
	UnassignRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError)
	OverrideRoles(source *entities.RolePayload) (*entities.UserInfo, errors.BaseError)
	ActiveUser(tenantId, userId string) (*entities.UserInfo, errors.BaseError)
	InactiveUser(tenantId, userId string) (*entities.UserInfo, errors.BaseError)
}
