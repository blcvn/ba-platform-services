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

func TestRegister(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.RegisterRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Registration",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "testuser",
					Password:    "SecurePass123!",
					Email:       "test@example.com",
					DisplayName: "Test User",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRegisterPayload
				mockTransform.On("Pb2ModelRegisterPayload", mock.Anything).Return(&entities.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "testuser",
					Password:    "SecurePass123!",
					Email:       "test@example.com",
					DisplayName: "Test User",
				}, nil)

				// Mock ValidateRegister
				mockValidator.On("ValidateRegister", mock.Anything).Return(nil)

				// Mock usecase.Register
				mockUsecase.On("Register", mock.Anything, mock.Anything).Return(&entities.UserInfo{
					UserId:      "user-001",
					TenantId:    "tenant-001",
					Email:       "test@example.com",
					Username:    "testuser",
					DisplayName: "Test User",
					Status:      1,
					Roles:       []string{"user"},
				}, nil)

				// Mock Model2PbUserInfo
				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "test@example.com",
					Username: "testuser",
					Roles:    []string{"user"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Register success",
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
					Email:    "test@example.com",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock Pb2ModelMetadata to return error
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
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Payload: &pb.RegisterPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
					Email:    "test@example.com",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies - metadata succeeds
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				// Signature validation fails
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelRegisterPayload Fails",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "weak",
					Email:    "invalid-email",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies - all succeed
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRegisterPayload to fail
				mockTransform.On("Pb2ModelRegisterPayload", mock.Anything).Return(
					(*entities.RegisterPayload)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidPayloadFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Transform register payload error",
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateRegister Fails (Weak Password)",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "weak",
					Email:    "test@example.com",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRegisterPayload
				mockTransform.On("Pb2ModelRegisterPayload", mock.Anything).Return(&entities.RegisterPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "weak",
					Email:    "test@example.com",
				}, nil)

				// Mock ValidateRegister to fail
				mockValidator.On("ValidateRegister", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrPasswordTooWeak)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate register error",
			expectUser:   false,
		},
		{
			name: "Usecase Error - User Already Exists",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "existinguser",
					Password:    "SecurePass123!",
					Email:       "existing@example.com",
					DisplayName: "Existing User",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRegisterPayload
				mockTransform.On("Pb2ModelRegisterPayload", mock.Anything).Return(&entities.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "existinguser",
					Password:    "SecurePass123!",
					Email:       "existing@example.com",
					DisplayName: "Existing User",
				}, nil)

				// Mock ValidateRegister
				mockValidator.On("ValidateRegister", mock.Anything).Return(nil)

				// Mock usecase.Register to fail with conflict error
				mockUsecase.On("Register", mock.Anything, mock.Anything).Return(
					(*entities.UserInfo)(nil),
					customerrors.NewBaseError(409, errors.New(constants.ErrUserAlreadyExists)),
				)
			},
			expectedCode: pb.ResultCode(409),
			expectedMsg:  "Register error",
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.RegisterRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "testuser",
					Password:    "SecurePass123!",
					Email:       "test@example.com",
					DisplayName: "Test User",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelRegisterPayload
				mockTransform.On("Pb2ModelRegisterPayload", mock.Anything).Return(&entities.RegisterPayload{
					TenantId:    "tenant-001",
					Username:    "testuser",
					Password:    "SecurePass123!",
					Email:       "test@example.com",
					DisplayName: "Test User",
				}, nil)

				// Mock ValidateRegister
				mockValidator.On("ValidateRegister", mock.Anything).Return(nil)

				// Mock usecase.Register
				mockUsecase.On("Register", mock.Anything, mock.Anything).Return(&entities.UserInfo{
					UserId:      "user-001",
					TenantId:    "tenant-001",
					Email:       "test@example.com",
					Username:    "testuser",
					DisplayName: "Test User",
					Status:      1,
					Roles:       []string{"user"},
				}, nil)

				// Mock Model2PbUserInfo to fail
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
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.Register(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "Register should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful registration")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed registration")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.LoginRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectToken  bool
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Login",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(&entities.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				}, nil)

				// Mock ValidateLogin
				mockValidator.On("ValidateLogin", mock.Anything).Return(nil)

				// Mock usecase.Login
				mockUsecase.On("Login", mock.Anything, mock.Anything).Return(&entities.UserData{
					UserInfo: &entities.UserInfo{
						UserId:   "user-001",
						TenantId: "tenant-001",
						Email:    "test@example.com",
						Username: "testuser",
						Status:   1,
						Roles:    []string{"user"},
					},
					Token: &entities.Token{
						AccessToken:  "access-token-123",
						RefreshToken: "refresh-token-456",
					},
				}, nil)

				// Mock Model2PbToken
				mockTransform.On("Model2PbToken", mock.Anything).Return(&pb.TokenMessage{
					AccessToken:  "access-token-123",
					RefreshToken: "refresh-token-456",
				}, nil)

				// Mock Model2PbUserInfo
				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "test@example.com",
					Username: "testuser",
					Roles:    []string{"user"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Login success",
			expectToken:  true,
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock Pb2ModelMetadata to return error
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Transform Payload Error - Pb2ModelLoginPayload Fails",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "weak",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies - all succeed
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload to fail
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(
					(*entities.LoginPayload)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidLoginPayloadFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Transform login payload error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Validation Error - ValidateLogin Fails",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "",
					Password: "SecurePass123!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(&entities.LoginPayload{
					TenantId: "tenant-001",
					Username: "",
					Password: "SecurePass123!",
				}, nil)

				// Mock ValidateLogin to fail
				mockValidator.On("ValidateLogin", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrUsernameRequired)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate login error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Usecase Error - Invalid Credentials",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "WrongPassword!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(&entities.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "WrongPassword!",
				}, nil)

				// Mock ValidateLogin
				mockValidator.On("ValidateLogin", mock.Anything).Return(nil)

				// Mock usecase.Login to fail with unauthorized error
				mockUsecase.On("Login", mock.Anything, mock.Anything).Return(
					(*entities.UserData)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrInvalidCredentials)),
				)
			},
			expectedCode: pb.ResultCode(401),
			expectedMsg:  "Login error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbToken Fails",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(&entities.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				}, nil)

				// Mock ValidateLogin
				mockValidator.On("ValidateLogin", mock.Anything).Return(nil)

				// Mock usecase.Login
				mockUsecase.On("Login", mock.Anything, mock.Anything).Return(&entities.UserData{
					UserInfo: &entities.UserInfo{
						UserId:   "user-001",
						TenantId: "tenant-001",
						Email:    "test@example.com",
						Username: "testuser",
						Status:   1,
						Roles:    []string{"user"},
					},
					Token: &entities.Token{
						AccessToken:  "access-token-123",
						RefreshToken: "refresh-token-456",
					},
				}, nil)

				// Mock Model2PbToken to fail
				mockTransform.On("Model2PbToken", mock.Anything).Return(
					(*pb.TokenMessage)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformToken)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.LoginRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-login-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Payload: &pb.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-login-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock Pb2ModelLoginPayload
				mockTransform.On("Pb2ModelLoginPayload", mock.Anything).Return(&entities.LoginPayload{
					TenantId: "tenant-001",
					Username: "testuser",
					Password: "SecurePass123!",
				}, nil)

				// Mock ValidateLogin
				mockValidator.On("ValidateLogin", mock.Anything).Return(nil)

				// Mock usecase.Login
				mockUsecase.On("Login", mock.Anything, mock.Anything).Return(&entities.UserData{
					UserInfo: &entities.UserInfo{
						UserId:   "user-001",
						TenantId: "tenant-001",
						Email:    "test@example.com",
						Username: "testuser",
						Status:   1,
						Roles:    []string{"user"},
					},
					Token: &entities.Token{
						AccessToken:  "access-token-123",
						RefreshToken: "refresh-token-456",
					},
				}, nil)

				// Mock Model2PbToken
				mockTransform.On("Model2PbToken", mock.Anything).Return(&pb.TokenMessage{
					AccessToken:  "access-token-123",
					RefreshToken: "refresh-token-456",
				}, nil)

				// Mock Model2PbUserInfo to fail
				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectToken:  false,
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.Login(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "Login should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectToken {
				assert.NotNil(t, response.Token, "Token should not be nil for successful login")
			} else {
				assert.Nil(t, response.Token, "Token should be nil for failed login")
			}

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful login")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed login")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.AuthenticationRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
	}{
		{
			name: "Happy Path - Successful Logout",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-logout-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-logout-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer valid-access-token")

				// Mock usecase.VerifyToken
				mockUsecase.On("VerifyToken", "Bearer valid-access-token").Return(&entities.UserSession{
					UserId:    "user-001",
					TenantId:  "tenant-001",
					SessionId: "session-123",
					RoleIds:   []string{"user"},
				}, nil)

				// Mock usecase.Logout
				mockUsecase.On("Logout", mock.Anything, "Bearer valid-access-token", mock.Anything).Return(nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Logout success",
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-logout-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock Pb2ModelMetadata to return error
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
		},
		{
			name: "Verify Token Error - Invalid Token",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-logout-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-logout-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer invalid-token")

				// Mock usecase.VerifyToken to fail
				mockUsecase.On("VerifyToken", "Bearer invalid-token").Return(
					(*entities.UserSession)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrInvalidOrExpiredToken)),
				)
			},
			expectedCode: pb.ResultCode_UNAUTHORIZED,
			expectedMsg:  "Verify token error",
		},
		{
			name: "Logout Usecase Error - Session Not Found",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-logout-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-logout-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer valid-access-token")

				// Mock usecase.VerifyToken
				mockUsecase.On("VerifyToken", "Bearer valid-access-token").Return(&entities.UserSession{
					UserId:    "user-001",
					TenantId:  "tenant-001",
					SessionId: "session-123",
					RoleIds:   []string{"user"},
				}, nil)

				// Mock usecase.Logout to fail
				mockUsecase.On("Logout", mock.Anything, "Bearer valid-access-token", mock.Anything).Return(
					customerrors.NewBaseError(404, errors.New(constants.ErrSessionNotFound)),
				)
			},
			expectedCode: pb.ResultCode(404),
			expectedMsg:  "Logout error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.Logout(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "Logout should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestVerifyToken(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.AuthenticationRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Token Verification",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-verify-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer valid-access-token")

				// Mock usecase.VerifyToken
				mockUsecase.On("VerifyToken", "Bearer valid-access-token").Return(&entities.UserSession{
					UserId:    "user-001",
					TenantId:  "tenant-001",
					SessionId: "session-123",
					RoleIds:   []string{"admin", "user"},
				}, nil)

				// Mock utilities.SetResponseHeader for X-User-ID
				mockUtilities.On("SetResponseHeader", mock.Anything, "X-User-ID", "user-001").Return(nil)

				// Mock utilities.SetResponseHeader for X-Tenant-ID
				mockUtilities.On("SetResponseHeader", mock.Anything, "X-Tenant-ID", "tenant-001").Return(nil)

				// Mock utilities.SetResponseHeaders for X-Roles
				mockUtilities.On("SetResponseHeaders", mock.Anything, "X-Roles", []string{"admin", "user"}).Return(nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Verify token success",
			expectUser:   true,
		},
		{
			name: "Verify Token Error - Invalid Token",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-verify-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer invalid-token")

				// Mock usecase.VerifyToken to fail
				mockUsecase.On("VerifyToken", "Bearer invalid-token").Return(
					(*entities.UserSession)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrInvalidOrExpiredToken)),
				)
			},
			expectedCode: pb.ResultCode(401),
			expectedMsg:  "Verify token error",
			expectUser:   false,
		},
		{
			name: "Verify Token Error - Token Expired",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-verify-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock utilities.GetHeaderKey for Authorization
				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer expired-token")

				// Mock usecase.VerifyToken to fail with expired error
				mockUsecase.On("VerifyToken", "Bearer expired-token").Return(
					(*entities.UserSession)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrTokenExpired)),
				)
			},
			expectedCode: pb.ResultCode(401),
			expectedMsg:  "Verify token error",
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.VerifyToken(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "VerifyToken should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful verification")
				assert.Equal(t, "user-001", response.User.UserId, "User ID should match")
				assert.Equal(t, "tenant-001", response.User.TenantId, "Tenant ID should match")
				assert.Equal(t, []string{"admin", "user"}, response.User.Roles, "Roles should match")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed verification")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestRevokeAccessToken(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.RevokeTokenRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
	}{
		{
			name: "Happy Path - Successful Token Revocation",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock usecase.RevokeAccessToken to succeed
				mockUsecase.On("RevokeAccessToken", mock.Anything, "valid-access-token-123").Return(nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Revoke Access Token success",
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken: "valid-access-token-123",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock Pb2ModelMetadata to return error
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Token: &pb.TokenMessage{
					AccessToken: "valid-access-token-123",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies - metadata succeeds
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "invalid-signature",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				// Signature validation fails
				mockValidator.On("ValidateSignature", mock.Anything).Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidSignature)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
		},
		{
			name: "Usecase Error - Token Not Found",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken: "non-existent-token",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock usecase.RevokeAccessToken to fail with not found error
				mockUsecase.On("RevokeAccessToken", mock.Anything, "non-existent-token").Return(
					customerrors.NewBaseError(404, errors.New(constants.ErrTokenNotFound)),
				)
			},
			expectedCode: pb.ResultCode(404),
			expectedMsg:  "Renew Access Token error",
		},
		{
			name: "Usecase Error - Token Already Revoked",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken: "already-revoked-token",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock usecase.RevokeAccessToken to fail with conflict error
				mockUsecase.On("RevokeAccessToken", mock.Anything, "already-revoked-token").Return(
					customerrors.NewBaseError(409, errors.New(constants.ErrTokenAlreadyRevoked)),
				)
			},
			expectedCode: pb.ResultCode(409),
			expectedMsg:  "Renew Access Token error",
		},
		{
			name: "Usecase Error - Internal Server Error",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken: "valid-access-token-123",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock usecase.RevokeAccessToken to fail with internal error
				mockUsecase.On("RevokeAccessToken", mock.Anything, "valid-access-token-123").Return(
					customerrors.NewBaseError(500, errors.New(constants.ErrDatabaseConnectionFailed)),
				)
			},
			expectedCode: pb.ResultCode(500),
			expectedMsg:  "Renew Access Token error",
		},
		{
			name: "Invalid Input - Empty Access Token",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken: "",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// Mock usecase.RevokeAccessToken to fail with bad request
				mockUsecase.On("RevokeAccessToken", mock.Anything, "").Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrAccessTokenRequired)),
				)
			},
			expectedCode: pb.ResultCode(400),
			expectedMsg:  "Renew Access Token error",
		},
		{
			name: "Malformed Mock - Nil Token Object",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: nil,
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				// Mock validateRequest dependencies
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				// No need to mock usecase since controller returns early when Token is nil
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.RevokeAccessToken(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "RevokeAccessToken should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.RevokeTokenRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
	}{
		{
			name: "Happy Path - Successful Refresh Token Revocation",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "valid-refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "valid-access-token-123", "valid-refresh-token-456").Return(nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Revoke Refresh Token success",
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "valid-refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "valid-refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-003",
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
		},
		{
			name: "Malformed Input - Nil Token Object",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: nil,
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Token is required",
		},
		{
			name: "Usecase Error - Refresh Token Not Found",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "non-existent-refresh-token",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "valid-access-token-123", "non-existent-refresh-token").Return(
					customerrors.NewBaseError(404, errors.New(constants.ErrRefreshTokenNotFound)),
				)
			},
			expectedCode: pb.ResultCode(404),
			expectedMsg:  "Revoke Refresh Token error",
		},
		{
			name: "Usecase Error - Token Mismatch",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "access-token-user-a",
					RefreshToken: "refresh-token-user-b",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "access-token-user-a", "refresh-token-user-b").Return(
					customerrors.NewBaseError(401, errors.New(constants.ErrTokenMismatch)),
				)
			},
			expectedCode: pb.ResultCode(401),
			expectedMsg:  "Revoke Refresh Token error",
		},
		{
			name: "Usecase Error - Token Already Revoked",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "access-token-123",
					RefreshToken: "already-revoked-refresh-token",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "access-token-123", "already-revoked-refresh-token").Return(
					customerrors.NewBaseError(409, errors.New(constants.ErrRefreshTokenAlreadyRevoked)),
				)
			},
			expectedCode: pb.ResultCode(409),
			expectedMsg:  "Revoke Refresh Token error",
		},
		{
			name: "Usecase Error - Internal Server Error",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "valid-refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "valid-access-token-123", "valid-refresh-token-456").Return(
					customerrors.NewBaseError(500, errors.New(constants.ErrDatabaseConnectionFailed)),
				)
			},
			expectedCode: pb.ResultCode(500),
			expectedMsg:  "Revoke Refresh Token error",
		},
		{
			name: "Invalid Input - Empty Access Token",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-009",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "",
					RefreshToken: "valid-refresh-token-456",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-009",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "", "valid-refresh-token-456").Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrAccessTokenRequired)),
				)
			},
			expectedCode: pb.ResultCode(400),
			expectedMsg:  "Revoke Refresh Token error",
		},
		{
			name: "Invalid Input - Empty Refresh Token",
			request: &pb.RevokeTokenRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-revoke-refresh-010",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
				Token: &pb.TokenMessage{
					AccessToken:  "valid-access-token-123",
					RefreshToken: "",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-revoke-refresh-010",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)
				mockUsecase.On("RevokeRefreshToken", mock.Anything, "valid-access-token-123", "").Return(
					customerrors.NewBaseError(400, errors.New(constants.ErrRefreshTokenRequired)),
				)
			},
			expectedCode: pb.ResultCode(400),
			expectedMsg:  "Revoke Refresh Token error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)
			ctx := context.Background()
			response, err := ctrl.RevokeRefreshToken(ctx, tt.request)
			assert.NoError(t, err, "RevokeRefreshToken should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}

func TestRenewAccessToken(t *testing.T) {
	tests := []struct {
		name         string
		request      *pb.AuthenticationRequest
		mockSetup    func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase)
		expectedCode pb.ResultCode
		expectedMsg  string
		expectToken  bool
		expectUser   bool
	}{
		{
			name: "Happy Path - Successful Token Renewal",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-001",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("valid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "valid-refresh-token").Return(&entities.UserData{
					Token: &entities.Token{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						ExpiresIn:    3600,
					},
					UserInfo: &entities.UserInfo{
						UserId:   "user-001",
						TenantId: "tenant-001",
						Email:    "user@example.com",
						Username: "testuser",
						Roles:    []string{"role-user"},
					},
				}, nil)

				mockTransform.On("Model2PbToken", mock.Anything).Return(&pb.TokenMessage{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					ExpiresIn:    3600,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(&pb.UserInfo{
					UserId:   "user-001",
					TenantId: "tenant-001",
					Email:    "user@example.com",
					Username: "testuser",
					Roles:    []string{"role-user"},
				}, nil)
			},
			expectedCode: pb.ResultCode_SUCCESS,
			expectedMsg:  "Renew token success",
			expectToken:  true,
			expectUser:   true,
		},
		{
			name: "Validate Request Error - Metadata Transform Fails",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-002",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(
					(*entities.Metadata)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrInvalidMetadataFormat)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Validate request error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Validate Request Error - Signature Validation Fails",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-003",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "invalid-signature",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-003",
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
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Usecase Error - Invalid Refresh Token",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-004",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("invalid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "invalid-refresh-token").Return(
					(*entities.UserData)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrInvalidRefreshToken)),
				)
			},
			expectedCode: pb.ResultCode_UNAUTHORIZED,
			expectedMsg:  "Renew token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Usecase Error - Refresh Token Expired",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-005",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("expired-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "expired-refresh-token").Return(
					(*entities.UserData)(nil),
					customerrors.NewBaseError(401, errors.New(constants.ErrRefreshTokenExpired)),
				)
			},
			expectedCode: pb.ResultCode_UNAUTHORIZED,
			expectedMsg:  "Renew token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Usecase Error - Session Not Found",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-006",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("valid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "valid-refresh-token").Return(
					(*entities.UserData)(nil),
					customerrors.NewBaseError(404, errors.New(constants.ErrSessionNotFound)),
				)
			},
			expectedCode: pb.ResultCode_NOT_FOUND,
			expectedMsg:  "Renew token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Usecase Error - Empty Access Token",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-007",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("valid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "", "valid-refresh-token").Return(
					(*entities.UserData)(nil),
					customerrors.NewBaseError(400, errors.New(constants.ErrAccessTokenRequired)),
				)
			},
			expectedCode: pb.ResultCode_BAD_REQUEST,
			expectedMsg:  "Renew token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbToken Fails",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-008",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("valid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "valid-refresh-token").Return(&entities.UserData{
					Token: &entities.Token{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						ExpiresIn:    3600,
					},
					UserInfo: &entities.UserInfo{
						UserId: "user-001",
					},
				}, nil)

				mockTransform.On("Model2PbToken", mock.Anything).Return(
					(*pb.TokenMessage)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformToken)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform token error",
			expectToken:  false,
			expectUser:   false,
		},
		{
			name: "Transform Error - Model2PbUserInfo Fails",
			request: &pb.AuthenticationRequest{
				Metadata: &pb.Metadata{
					RequestId:   "req-renew-009",
					RequestTime: 1234567890,
					Version:     "1.0",
				},
				Signature: &pb.Signature{
					SType: pb.Signature_NO_USE_TYPE,
					S:     "signature-string",
				},
			},
			mockSetup: func(mockUtilities *controllers.MockIUtilities, mockTransform *controllers.MockITransform, mockValidator *controllers.MockIValidator, mockUsecase *controllers.MockIAuthUsecase) {
				mockTransform.On("Pb2ModelMetadata", mock.Anything).Return(&entities.Metadata{
					RequestId:   "req-renew-009",
					RequestTime: 1234567890,
					Version:     "1.0",
				}, nil)
				mockTransform.On("Pb2ModelSignature", mock.Anything).Return(&entities.Signature{
					Type: entities.SignatureType_NO_USE_TYPE,
					S:    "signature-string",
				}, nil)
				mockValidator.On("ValidateMetadata", mock.Anything).Return(nil)
				mockValidator.On("ValidateSignature", mock.Anything).Return(nil)

				mockUtilities.On("GetHeaderKey", mock.Anything, "Authorization").Return("Bearer old-access-token")
				mockUtilities.On("GetHeaderKey", mock.Anything, "RefreshToken").Return("valid-refresh-token")

				mockUsecase.On("RenewAccessToken", mock.Anything, "Bearer old-access-token", "valid-refresh-token").Return(&entities.UserData{
					Token: &entities.Token{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						ExpiresIn:    3600,
					},
					UserInfo: &entities.UserInfo{
						UserId: "user-001",
					},
				}, nil)

				mockTransform.On("Model2PbToken", mock.Anything).Return(&pb.TokenMessage{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					ExpiresIn:    3600,
				}, nil)

				mockTransform.On("Model2PbUserInfo", mock.Anything).Return(
					(*pb.UserInfo)(nil),
					customerrors.NewBaseError(500, errors.New(constants.ErrFailedToTransformUserInfo)),
				)
			},
			expectedCode: pb.ResultCode_INTERNAL,
			expectedMsg:  "Transform user info error",
			expectToken:  false,
			expectUser:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockUtilities := controllers.NewMockIUtilities(t)
			mockTransform := controllers.NewMockITransform(t)
			mockValidator := controllers.NewMockIValidator(t)
			mockUsecase := controllers.NewMockIAuthUsecase(t)

			// Setup mocks
			tt.mockSetup(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Create controller using constructor
			ctrl := controllers.NewAuthenController(mockUtilities, mockTransform, mockValidator, mockUsecase)

			// Execute
			ctx := context.Background()
			response, err := ctrl.RenewAccessToken(ctx, tt.request)

			// Assert
			assert.NoError(t, err, "RenewAccessToken should not return error")
			assert.NotNil(t, response, "Response should not be nil")
			assert.NotNil(t, response.Result, "Result should not be nil")
			assert.Equal(t, tt.expectedCode, response.Result.Code, "Result code should match")
			assert.Contains(t, response.Result.Message, tt.expectedMsg, "Result message should contain expected text")

			if tt.expectToken {
				assert.NotNil(t, response.Token, "Token should not be nil for successful renewal")
			} else {
				assert.Nil(t, response.Token, "Token should be nil for failed renewal")
			}

			if tt.expectUser {
				assert.NotNil(t, response.User, "User should not be nil for successful renewal")
			} else {
				assert.Nil(t, response.User, "User should be nil for failed renewal")
			}

			// Verify metadata and signature are echoed back
			assert.Equal(t, tt.request.Metadata, response.Metadata, "Metadata should be echoed back")
			assert.Equal(t, tt.request.Signature, response.Signature, "Signature should be echoed back")
		})
	}
}
