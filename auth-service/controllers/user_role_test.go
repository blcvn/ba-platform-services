package controllers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	customerrors "github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/controllers"
	"github.com/blcvn/backend/services/auth-service/entities"
	pb "github.com/blcvn/kratos-proto/go/authen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAssignRole(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.UserRoleRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Role Assignment",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin", "role-user"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRolePayload
				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin", "role-user"},
				}, nil)

				// Mock GetHeaderKey and GetHeaderListString
				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})

				// Mock ValidateRoles
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				// Mock usecase.AssignRoles
				mockUsecase.On("AssignRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin", "role-user"},
					Status:   1,
				}, nil)

				// Mock Model2PbUserInfo
				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin", "role-user"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Assign role success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelRolePayload Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(
					(*entities.RolePayload)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidRolePayloadFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Transform role payload error",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateRoles Fails (Insufficient Permissions)",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-user"})

				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-user"}, mock.Anything).Return(
					customerrors.NewBaseError(403, errors.New(constants.ErrInsufficientPermissions)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Not Found",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("AssignRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrUserNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Assign role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - Role Not Found",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"non-existent-role"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"non-existent-role"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("AssignRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrRoleNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Assign role error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-assign-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-assign-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("AssignRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIRoleUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewUserRoleController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.AssignRole(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "AssignRole should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful assignment")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed assignment")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestUnassignRole(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.UserRoleRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Role Unassignment",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-user"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-user"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("UnassignRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Unassign role success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelRolePayload Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(
					(*entities.RolePayload)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidRolePayloadFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Transform role payload error",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateRoles Fails (Insufficient Permissions)",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-user"})

				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-user"}, mock.Anything).Return(
					customerrors.NewBaseError(403, errors.New(constants.ErrInsufficientPermissions)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Not Found",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("UnassignRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrUserNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Unassign role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - Role Not Assigned",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-not-assigned"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-not-assigned"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("UnassignRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("role not assigned to user")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Unassign role error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-unassign-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-unassign-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("UnassignRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIRoleUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewUserRoleController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.UnassignRole(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "UnassignRole should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful unassignment")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed unassignment")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestOverrideRole(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.UserRoleRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Role Override",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-manager", "role-viewer"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-manager", "role-viewer"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("OverrideRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-manager", "role-viewer"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-manager", "role-viewer"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Override role success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelRolePayload Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(
					(*entities.RolePayload)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidRolePayloadFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Transform role payload error",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateRoles Fails (Insufficient Permissions)",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-user"})

				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-user"}, mock.Anything).Return(
					customerrors.NewBaseError(403, errors.New(constants.ErrInsufficientPermissions)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Not Found",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("OverrideRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrUserNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Override role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - Invalid Role Configuration",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-invalid"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-invalid"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("OverrideRoles", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("invalid role configuration")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Override role error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.UserRoleRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-override-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					Roles:    []string{"role-admin"},
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-override-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelRolePayload", mock.Anything).Return(&entities.RolePayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
					RoleIds:  []string{"role-admin"},
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateRoles", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("OverrideRoles", mock.Anything).Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-admin"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIRoleUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewUserRoleController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.OverrideRole(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "OverrideRole should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful override")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed override")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestActiveUser(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.UserStatusRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful User Activation",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})

				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("ActiveUser", "tenant-001", "user-001").Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   pb.Status_ACTIVE,
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Active user success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelUserStatusPayload Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "",
					UserId:   "",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("invalid user status payload")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "invalid user status payload",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateUser Fails (Insufficient Permissions)",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-user"})

				mockValidator.On("ValidateUser", "tenant-001", []string{"role-user"}, mock.Anything).Return(
					customerrors.NewBaseError(403, errors.New(constants.ErrInsufficientPermissions)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Not Found",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("ActiveUser", "tenant-001", "non-existent-user").Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrUserNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Active user error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Already Active",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("ActiveUser", "tenant-001", "user-001").Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("user already active")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Active user error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-active-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-active-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("ActiveUser", "tenant-001", "user-001").Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   1,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIRoleUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewUserRoleController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.ActiveUser(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "ActiveUser should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful activation")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed activation")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestInactiveUser(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.UserStatusRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful User Deactivation",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})

				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("InactiveUser", "tenant-001", "user-001").Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   0,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   pb.Status_INACTIVE,
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Inactive user success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelUserStatusPayload Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "",
					UserId:   "",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("invalid user status payload")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "invalid user status payload",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateUser Fails (Insufficient Permissions)",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-user"})

				mockValidator.On("ValidateUser", "tenant-001", []string{"role-user"}, mock.Anything).Return(
					customerrors.NewBaseError(403, errors.New(constants.ErrInsufficientPermissions)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate role error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Not Found",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "non-existent-user",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("InactiveUser", "tenant-001", "non-existent-user").Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrUserNotFound)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Inactive user error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Already Inactive",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("InactiveUser", "tenant-001", "user-001").Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(400, errors.New("user already inactive")),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Inactive user error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.UserStatusRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-inactive-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.UserStatusPayload{
					TenantId: "tenant-001",
					UserId:   "user-001",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIRoleUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-inactive-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockTransform.On("Pb2ModelUserStatusPayload", mock.Anything).Return(&entities.UserInfo{
					TenantId: "tenant-001",
					UserId:   "user-001",
				}, nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "X-Tenant-ID").Return("tenant-001")
				mockUtilities.On("GetHeaderListString", mock.Anything, "X-Roles").Return([]string{"role-super-admin"})
				mockValidator.On("ValidateUser", "tenant-001", []string{"role-super-admin"}, mock.Anything).Return(nil)

				mockUsecase.On("InactiveUser", "tenant-001", "user-001").Return(&entities.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
					Status:   0,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIRoleUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewUserRoleController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.InactiveUser(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "InactiveUser should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful deactivation")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed deactivation")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}
