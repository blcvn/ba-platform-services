package helper

import (
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/entities"
	pb "github.com/blcvn/kratos-proto/go/authen"
)

type transform struct {
}

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

func (t *transform) Pb2ModelRegisterPayload(source *pb.RegisterPayload) (*entities.RegisterPayload, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrPayloadNotAllowedNil, "RegisterPayload"))
	}
	return &entities.RegisterPayload{
		TenantId:    source.TenantId,
		Username:    source.Username,
		Password:    source.Password,
		Email:       source.Email,
		DisplayName: source.DisplayName,
	}, nil
}

func (t *transform) Pb2ModelLoginPayload(source *pb.LoginPayload) (*entities.LoginPayload, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(int(pb.ResultCode_BAD_REQUEST), fmt.Errorf(constants.ErrLoginPayloadNil))
	}
	return &entities.LoginPayload{
		TenantId: source.TenantId,
		Username: source.Username,
		Password: source.Password,
		GToken:   "",
		Method:   entities.LoginMethod_USERNAME_PASSWORD,
	}, nil
}

func (t *transform) Pb2ModelLoginWithGooglePayload(source *pb.LoginWithGooglePayload) (*entities.LoginPayload, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(int(pb.ResultCode_BAD_REQUEST), fmt.Errorf(constants.ErrLoginPayloadNil))
	}
	return &entities.LoginPayload{
		TenantId: source.TenantId,
		Username: "",
		Password: "",
		GToken:   source.GoogleIdToken,
		Method:   entities.LoginMethod_GOOGLE,
	}, nil
}

func (t *transform) Pb2ModelRolePayload(source *pb.RolePayload) (*entities.RolePayload, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrPayloadNotAllowedNil, "RolePayload"))
	}
	return &entities.RolePayload{
		TenantId: source.TenantId,
		UserId:   source.UserId,
		RoleIds:  append([]string{}, source.Roles...),
	}, nil
}

func (t *transform) Pb2ModelUserStatusPayload(source *pb.UserStatusPayload) (*entities.UserInfo, errors.BaseError) {
	if source == nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrPayloadNotAllowedNil, "UserStatus"))
	}
	return &entities.UserInfo{
		UserId:   source.UserId,
		TenantId: source.TenantId,
	}, nil
}

func (t *transform) Pb2ModelPagination(source *pb.Pagination) (*entities.Pagination, errors.BaseError) {
	if source == nil {
		// Return default pagination if not provided
		return &entities.Pagination{
			Page:  1,
			Limit: 10,
			Total: 0,
		}, nil
	}
	return &entities.Pagination{
		Page:  source.Page,
		Limit: source.Limit,
		Total: source.Total,
	}, nil
}

func (t *transform) Model2PbMetadata(source *entities.Metadata) (*pb.Metadata, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &pb.Metadata{
		RequestId:   source.RequestId,
		RequestTime: source.RequestTime,
		Version:     source.Version,
	}, nil
}

func (t *transform) Model2PbSignature(source *entities.Signature) (*pb.Signature, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &pb.Signature{
		SType: pb.Signature_SignatureType(source.Type),
		S:     source.S,
		B:     source.B,
	}, nil
}

func (t *transform) Model2PbUserInfo(source *entities.UserInfo) (*pb.UserInfo, errors.BaseError) {
	if source == nil {
		return nil, nil
	}

	return &pb.UserInfo{
		UserId:     source.UserId,
		TenantId:   source.TenantId,
		Email:      source.Email,
		Username:   source.Username,
		Status:     pb.Status(source.Status),
		Roles:      append([]string{}, source.Roles...),
		Attributes: cloneStringMap(source.Attributes),
	}, nil
}

func (t *transform) Model2PbToken(source *entities.Token) (*pb.TokenMessage, errors.BaseError) {
	if source == nil {
		return nil, nil
	}
	return &pb.TokenMessage{
		AccessToken:  source.AccessToken,
		RefreshToken: source.RefreshToken,
		ExpiresIn:    source.ExpiresIn,
		ExpiresAt:    source.ExpiresAt,
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

func (t *transform) Model2PbListUserRole(source []*entities.UserInfo) ([]string, errors.BaseError) {
	if source == nil {
		return []string{}, nil
	}

	// Extract all unique role IDs from all users
	roleMap := make(map[string]bool)
	for _, user := range source {
		if user != nil && user.Roles != nil {
			for _, roleId := range user.Roles {
				roleMap[roleId] = true
			}
		}
	}

	// Convert map to slice
	roles := make([]string, 0, len(roleMap))
	for roleId := range roleMap {
		roles = append(roles, roleId)
	}

	return roles, nil
}

func cloneStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}

	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
