package constants

// Error messages for validation
const (
	// Payload validation errors
	ErrRegisterPayloadRequired = "register payload is required"
	ErrLoginPayloadRequired    = "login payload is required"
	ErrRolePayloadRequired     = "role payload is required"
	ErrPayloadNotAllowedNil    = "%s is not allowed to be nil" // format: payload name
	ErrLoginPayloadNil         = "login payload is nil"

	// Field validation errors
	ErrTenantIDRequired              = "tenant id is required"
	ErrUsernamePasswordEmailRequired = "username, password, and email are required"
	ErrGoogleTokenRequired           = "google token is required"
	ErrUserIDCannotBeEmpty           = "userId cannot be empty"
	ErrRoleIDsCannotBeEmpty          = "roleIds cannot be empty"

	// Format validation errors
	ErrInvalidUserIDFormat   = "invalid userId format"
	ErrInvalidTenantIDFormat = "invalid tenantId format"
	ErrInvalidRoleIDFormat   = "invalid roleId format: %s" // format: roleId

	// Authentication errors
	ErrInvalidPassword         = "invalid password"
	ErrUsernamePasswordInvalid = "username or password is invalid"
	ErrInvalidCredentials      = "invalid credentials"

	// Token errors
	ErrUnexpectedSigningMethod = "unexpected signing method: %v" // format: method
	ErrInvalidToken            = "invalid token: %v"             // format: error
	ErrInvalidTokenType        = "invalid token type"
	ErrInvalidTokenClaims      = "invalid token claims"
	ErrInvalidTokenSimple      = "invalid token"
	ErrInvalidRefreshToken     = "invalid refresh token"
	ErrRefreshTokenExpired     = "refresh token expired"
	ErrAccessTokenRequired     = "access token is required"
	ErrTokenRevoked            = "token has been revoked"
	ErrTokenExpired            = "token has expired"

	// User errors
	ErrUsernameAlreadyExists = "username already exists"
	ErrUserNotFound          = "user not found"
	ErrUserAlreadyExists     = "user already exists"

	// Role errors
	ErrRoleNotFound              = "role not found"
	ErrTenantNotFoundOrNotActive = "tenant not found or not active"
	ErrRolesNotFoundOrInvalid    = "one or more roles not found, not active, or do not belong to the tenant"

	// Database errors
	ErrFailedToQueryUserRoles      = "failed to query user roles: %v"  // format: error
	ErrFailedToQueryTenant         = "failed to query tenant: %v"      // format: error
	ErrFailedToQueryRoles          = "failed to query roles: %v"       // format: error
	ErrFailedToUpsertUserRoles     = "failed to upsert user roles: %v" // format: error
	ErrFailedToDeleteUserRoles     = "failed to delete user roles: %v" // format: error
	ErrFailedToCheckTokenBlacklist = "failed to check token blacklist"
	ErrFailedToQueryUser           = "failed to query user: %v"         // format: error
	ErrFailedToUpdateUserStatus    = "failed to update user status: %v" // format: error
	ErrDatabaseConnectionFailed    = "database connection failed"
	ErrSessionNotFound             = "session not found"

	// Permission errors
	ErrInsufficientPermissions = "insufficient permissions"

	// Transform errors
	ErrFailedToTransformUserInfo = "failed to transform user info"
	ErrFailedToTransformToken    = "failed to transform token"

	// Metadata/Signature errors
	ErrInvalidMetadataFormat     = "invalid metadata format"
	ErrInvalidSignature          = "invalid signature"
	ErrInvalidPayloadFormat      = "invalid payload format"
	ErrInvalidRolePayloadFormat  = "invalid role payload format"
	ErrInvalidLoginPayloadFormat = "invalid login payload format"

	// Other errors
	ErrPasswordTooWeak            = "password too weak"
	ErrUsernameRequired           = "username is required"
	ErrRefreshTokenRequired       = "refresh token is required"
	ErrTokenNotFound              = "token not found"
	ErrRefreshTokenNotFound       = "refresh token not found"
	ErrTokenAlreadyRevoked        = "token already revoked"
	ErrRefreshTokenAlreadyRevoked = "refresh token already revoked"
	ErrTokenMismatch              = "token mismatch"
	ErrInvalidOrExpiredToken      = "invalid or expired token"
)

// Controller response messages (for pb.Result Message field)
const (
	// Success messages
	MsgRegisterSuccess           = "Register success"
	MsgLoginSuccess              = "Login success"
	MsgLogoutSuccess             = "Logout success"
	MsgVerifyTokenSuccess        = "Verify token success"
	MsgRenewTokenSuccess         = "Renew token success"
	MsgRevokeAccessTokenSuccess  = "Revoke Access Token success"
	MsgRevokeRefreshTokenSuccess = "Revoke Refresh Token success"
	MsgAssignRoleSuccess         = "Assign role success"
	MsgUnassignRoleSuccess       = "Unassign role success"
	MsgOverrideRoleSuccess       = "Override role success"
	MsgActiveUserSuccess         = "Active user success"
	MsgInactiveUserSuccess       = "Inactive user success"
	MsgListRoleSuccess           = "List roles success"

	// Error message templates (with %s for error details)
	MsgValidateRequestError          = "Validate request error %s"
	MsgTransformRegisterPayloadError = "Transform register payload error %s"
	MsgValidateRegisterError         = "Validate register error %s"
	MsgRegisterError                 = "Register error %s"
	MsgTransformUserInfoError        = "Transform user info error %s"
	MsgTransformLoginPayloadError    = "Transform login payload error %s"
	MsgValidateLoginError            = "Validate login error %s"
	MsgLoginError                    = "Login error %s"
	MsgTransformTokenError           = "Transform token error %s"
	MsgVerifyTokenError              = "Verify token error %s"
	MsgLogoutError                   = "Logout error %s"
	MsgRenewTokenError               = "Renew token error %s"
	MsgRenewAccessTokenError         = "Renew Access Token error %s"
	MsgRevokeRefreshTokenError       = "Revoke Refresh Token error %s"
	MsgTransformRolePayloadError     = "Transform role payload error %s"
	MsgValidateRoleError             = "Validate role error %s"
	MsgAssignRoleError               = "Assign role error %s"
	MsgUnassignRoleError             = "Unassign role error %s"
	MsgOverrideRoleError             = "Override role error %s"
	MsgActiveUserError               = "Active user error %s"
	MsgInactiveUserError             = "Inactive user error %s"
	MsgTransformUserStatusError      = "Transform user status error %s"
	MsgListRoleError                 = "List roles error %s"
	MsgTransformPaginationError      = "Transform pagination error %s"
	MsgTransformUserRoleListError    = "Transform user role list error %s"
)
