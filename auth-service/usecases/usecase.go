package usecases

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/auth/credentials/idtoken"
	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/entities"
	"github.com/blcvn/backend/services/auth-service/helper"
	"github.com/google/uuid"
)

type authUsecase struct {
	userRepository    iUserRepository
	sessionRepository iSessionRepository
	tokenRepository   iTokenRepository
	auditRepository   iAuditLogRepository
	hashUtilities     iHashUtilities
	auditHelper       *helper.AuditHelper
}

func (u *authUsecase) Register(ctx context.Context, source *entities.RegisterPayload) (*entities.UserInfo, errors.BaseError) {
	tenantUUID, _ := uuid.Parse(source.TenantId)
	var userID *uuid.UUID
	var result = helper.AuditResultSuccess

	// Check if user already exists
	existingUser, err := u.userRepository.GetByUserName(source.Username)
	if err == nil && existingUser != nil {
		result = helper.AuditResultFailure
		// Log failed registration attempt
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, nil, nil,
			helper.AuditActionRegister, result,
			helper.ResourceTypeUser, nil,
			map[string]interface{}{"username": source.Username, "reason": "username already exists"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errors.NewBaseError(errors.CONFLICT_ERROR, fmt.Errorf(constants.ErrUsernameAlreadyExists))
	}

	// Hash password before storing
	hashedPassword, err := u.hashUtilities.HashPassword(source.Password)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, nil, nil,
			helper.AuditActionRegister, result,
			helper.ResourceTypeUser, nil,
			map[string]interface{}{"username": source.Username, "reason": "password hashing failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Update payload with hashed password
	source.Password = hashedPassword

	// Create user through repository
	userInfo, err := u.userRepository.CreateUser(source)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, nil, nil,
			helper.AuditActionRegister, result,
			helper.ResourceTypeUser, nil,
			map[string]interface{}{"username": source.Username, "reason": "user creation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Parse user ID for audit log
	if parsedUserID, parseErr := uuid.Parse(userInfo.UserId); parseErr == nil {
		userID = &parsedUserID
	}

	// Log successful registration
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, userID, nil,
		helper.AuditActionRegister, result,
		helper.ResourceTypeUser, userID,
		map[string]interface{}{"username": source.Username, "email": source.Email},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return userInfo, nil
}

func (u *authUsecase) Login(ctx context.Context, source *entities.LoginPayload) (*entities.UserData, errors.BaseError) {
	tenantUUID, _ := uuid.Parse(source.TenantId)
	var userID *uuid.UUID
	var sessionUUID *uuid.UUID
	result := helper.AuditResultSuccess

	user, err := u.userRepository.GetByUserName(source.Username)
	if err != nil {
		result = helper.AuditResultFailure
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, nil, nil,
			helper.AuditActionLogin, result,
			helper.ResourceTypeUser, nil,
			map[string]interface{}{"username": source.Username, "reason": "user not found"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Parse user ID
	if parsedUserID, parseErr := uuid.Parse(user.UserId); parseErr == nil {
		userID = &parsedUserID
	}

	// Verify password using bcrypt
	err = u.hashUtilities.VerifyPassword(user.Password, source.Password)
	if err != nil {
		result = helper.AuditResultFailure
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, nil,
			helper.AuditActionLogin, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"username": source.Username, "reason": "invalid password"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUsernamePasswordInvalid))
	}

	// Generate opaque refresh token
	refreshToken, err := u.hashUtilities.GenerateOpaqueToken()
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, nil,
			helper.AuditActionLogin, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"username": source.Username, "reason": "token generation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Create session with 7 days expiry
	expiresAt := time.Now().Add(time.Hour * 24 * 7)
	sessionID, err := u.sessionRepository.CreateSession(user.UserId, refreshToken, expiresAt)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, nil,
			helper.AuditActionLogin, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"username": source.Username, "reason": "session creation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Parse session ID
	if parsedSessionID, parseErr := uuid.Parse(sessionID); parseErr == nil {
		sessionUUID = &parsedSessionID
	}

	// Generate token pair with the same refresh token stored in session
	token, err := u.hashUtilities.GenerateTokenPairWithRefreshToken(sessionID, refreshToken, user)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, sessionUUID,
			helper.AuditActionLogin, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"username": source.Username, "reason": "token pair generation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, err
	}

	// Log successful login
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, userID, sessionUUID,
		helper.AuditActionLogin, result,
		helper.ResourceTypeSession, sessionUUID,
		map[string]interface{}{"username": source.Username},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return &entities.UserData{
		UserInfo: user,
		Token:    token,
	}, nil
}

func (u *authUsecase) LoginWithGoogle(ctx context.Context, source *entities.LoginPayload) (*entities.UserData, errors.BaseError) {
	tenantUUID, _ := uuid.Parse(source.TenantId)
	var userID *uuid.UUID
	var sessionUUID *uuid.UUID
	result := helper.AuditResultSuccess

	// 1. Verify Google Token
	payload, err := idtoken.Validate(ctx, source.GToken, "")
	if err != nil {
		result = helper.AuditResultFailure
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, nil, nil,
			helper.AuditActionLoginGoogle, result,
			helper.ResourceTypeUser, nil,
			map[string]interface{}{"reason": "invalid google token", "error": err.Error()},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf("invalid google token"))
	}

	// 2. Extract user info from Google token
	email, ok := payload.Claims["email"].(string)
	if !ok {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf("email not found in google token"))
	}
	name, _ := payload.Claims["name"].(string)
	sub, _ := payload.Claims["sub"].(string)         // Google OAuth subject ID
	picture, _ := payload.Claims["picture"].(string) // Avatar URL

	if sub == "" {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf("sub (google ID) not found in token"))
	}

	var user *entities.UserInfo

	// 3. Try to find user by Google ID first (proper OAuth account linking)
	user, errRepo := u.userRepository.GetByGoogleID(sub)
	if errRepo != nil {
		// If not found by Google ID, try to find by email
		if errRepo.GetCode() == errors.BAD_REQUEST {
			user, errRepo = u.userRepository.GetByEmail(email)
			if errRepo != nil {
				// User doesn't exist at all - auto-register
				if errRepo.GetCode() == errors.BAD_REQUEST {
					randomPassword, _ := u.hashUtilities.GenerateOpaqueToken()
					registerPayload := &entities.RegisterPayload{
						TenantId:    source.TenantId,
						Username:    email, // Use email as username
						Password:    randomPassword,
						Email:       email,
						DisplayName: name,
					}

					newUser, regErr := u.Register(ctx, registerPayload)
					if regErr != nil {
						return nil, regErr
					}

					// Link Google account to newly registered user
					if linkErr := u.userRepository.UpdateGoogleOAuth(newUser.UserId, sub, picture); linkErr != nil {
						// Log error but don't fail login
						auditLog := u.auditHelper.CreateAuditLogEntry(
							ctx, tenantUUID, userID, nil,
							helper.AuditActionLoginGoogle, helper.AuditResultError,
							helper.ResourceTypeUser, userID,
							map[string]interface{}{"email": email, "reason": "failed to link google account", "error": linkErr.Error()},
						)
						_ = u.auditRepository.CreateAuditLog(auditLog)
					}

					// Refresh user data to include google_id
					user, _ = u.userRepository.GetByUserID(newUser.UserId)
					if user == nil {
						user = newUser
					}
				} else {
					return nil, errRepo
				}
			} else {
				// User exists by email but not linked to Google yet - link the account
				if linkErr := u.userRepository.UpdateGoogleOAuth(user.UserId, sub, picture); linkErr != nil {
					// Log error but don't fail login
					auditLog := u.auditHelper.CreateAuditLogEntry(
						ctx, tenantUUID, userID, nil,
						helper.AuditActionLoginGoogle, helper.AuditResultError,
						helper.ResourceTypeUser, userID,
						map[string]interface{}{"email": email, "reason": "failed to link google account", "error": linkErr.Error()},
					)
					_ = u.auditRepository.CreateAuditLog(auditLog)
				}

				// Refresh user data to include google_id
				refreshedUser, _ := u.userRepository.GetByUserID(user.UserId)
				if refreshedUser != nil {
					user = refreshedUser
				}
			}
		} else {
			return nil, errRepo
		}
	}

	// 4. Generate Tokens (logic similar to Login)

	// Parse user ID
	if parsedUserID, parseErr := uuid.Parse(user.UserId); parseErr == nil {
		userID = &parsedUserID
	}

	// Generate opaque refresh token
	refreshToken, errBase := u.hashUtilities.GenerateOpaqueToken()
	if errBase != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, nil,
			helper.AuditActionLoginGoogle, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"email": email, "reason": "token generation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errBase
	}

	// Create session with 7 days expiry
	expiresAt := time.Now().Add(time.Hour * 24 * 7)
	sessionID, errBase := u.sessionRepository.CreateSession(user.UserId, refreshToken, expiresAt)
	if errBase != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, nil,
			helper.AuditActionLoginGoogle, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"email": email, "reason": "session creation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errBase
	}

	// Parse session ID
	if parsedSessionID, parseErr := uuid.Parse(sessionID); parseErr == nil {
		sessionUUID = &parsedSessionID
	}

	// Generate token pair
	token, errBase := u.hashUtilities.GenerateTokenPairWithRefreshToken(sessionID, refreshToken, user)
	if errBase != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, userID, sessionUUID,
			helper.AuditActionLoginGoogle, result,
			helper.ResourceTypeUser, userID,
			map[string]interface{}{"email": email, "reason": "token pair generation failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return nil, errBase
	}

	// Log successful login
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, userID, sessionUUID,
		helper.AuditActionLoginGoogle, result,
		helper.ResourceTypeSession, sessionUUID,
		map[string]interface{}{"email": email, "provider": "google", "google_id": sub},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return &entities.UserData{
		UserInfo: user,
		Token:    token,
	}, nil
}

func (u *authUsecase) Logout(ctx context.Context, accessToken string, userSession *entities.UserSession) errors.BaseError {
	tenantUUID, _ := uuid.Parse(userSession.TenantId)
	userUUID, _ := uuid.Parse(userSession.UserId)
	sessionUUID, _ := uuid.Parse(userSession.SessionId)
	result := helper.AuditResultSuccess

	// Delete only the specific session associated with this access token
	// This allows the user to remain logged in on other devices
	err := u.sessionRepository.DeleteSession(userSession.SessionId)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, &userUUID, &sessionUUID,
			helper.AuditActionLogout, result,
			helper.ResourceTypeSession, &sessionUUID,
			map[string]interface{}{"reason": "session deletion failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return err
	}

	// Blacklist the current access token (15 minutes until expiry)
	// This ensures immediate invalidation of the current access token
	err = u.tokenRepository.BlacklistAccessToken(accessToken, time.Minute*15)
	if err != nil {
		result = helper.AuditResultError
		auditLog := u.auditHelper.CreateAuditLogEntry(
			ctx, tenantUUID, &userUUID, &sessionUUID,
			helper.AuditActionLogout, result,
			helper.ResourceTypeToken, nil,
			map[string]interface{}{"reason": "token blacklist failed"},
		)
		_ = u.auditRepository.CreateAuditLog(auditLog)
		return err
	}

	// Log successful logout
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, &userUUID, &sessionUUID,
		helper.AuditActionLogout, result,
		helper.ResourceTypeSession, &sessionUUID,
		map[string]interface{}{},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return nil
}

func (u *authUsecase) RenewAccessToken(ctx context.Context, accessToken, refreshToken string) (*entities.UserData, errors.BaseError) {
	// Get session by refresh token
	sessionID, userID, expiresAt, err := u.sessionRepository.GetSessionByRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRefreshToken))
	}

	// Check if session is expired
	if time.Now().After(expiresAt) {
		// Clean up expired session
		_ = u.sessionRepository.DeleteSession(sessionID)
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrRefreshTokenExpired))
	}

	// Blacklist old access token if provided
	if accessToken != "" {
		_ = u.tokenRepository.BlacklistAccessToken(accessToken, time.Minute*15)
	}

	// Get user info (now includes roles from database)
	user, err := u.userRepository.GetByUserID(userID)
	if err != nil {
		return nil, err
	}

	// Generate new token pair with CORRECT parameter order: (sessionID, refreshToken, user)
	newToken, err := u.hashUtilities.GenerateTokenPairWithRefreshToken(sessionID, refreshToken, user)
	if err != nil {
		return nil, err
	}

	// Log successful token refresh
	tenantUUID, _ := uuid.Parse(user.TenantId)
	userUUID, _ := uuid.Parse(user.UserId)
	sessionUUID, _ := uuid.Parse(sessionID)
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, &userUUID, &sessionUUID,
		helper.AuditActionTokenRefresh, helper.AuditResultSuccess,
		helper.ResourceTypeToken, nil,
		map[string]interface{}{},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return &entities.UserData{
		UserInfo: user,
		Token:    newToken,
	}, nil
}

func (u *authUsecase) VerifyToken(accessToken string) (*entities.UserSession, errors.BaseError) {
	if accessToken == "" {
		return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrAccessTokenRequired))
	}
	// Check if token is blacklisted
	isBlacklisted, err := u.tokenRepository.IsAccessTokenBlacklisted(accessToken)
	if err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToCheckTokenBlacklist))
	}
	if isBlacklisted {
		return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrTokenRevoked))
	}

	// Verify and parse access token
	userSession, err := u.hashUtilities.VerifyAccessToken(accessToken)
	if err != nil {
		return nil, errors.NewBaseError(errors.UNAUTHORIZED, err)
	}

	return userSession, nil
}

func (u *authUsecase) RevokeAccessToken(ctx context.Context, accessToken string) errors.BaseError {
	return u.revokeAccessToken(ctx, accessToken)
}

func (u *authUsecase) RevokeRefreshToken(ctx context.Context, accessToken, refreshToken string) errors.BaseError {
	if accessToken != "" {
		if err := u.RevokeAccessToken(ctx, accessToken); err != nil {
			return err
		}
	}
	// Find session by refresh token
	sessionID, userID, _, err := u.sessionRepository.GetSessionByRefreshToken(refreshToken)
	if err != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidRefreshToken))
	}

	// Delete session from database
	err = u.sessionRepository.DeleteSession(sessionID)
	if err != nil {
		return err
	}

	// Log session revocation
	userUUID, _ := uuid.Parse(userID)
	sessionUUID, _ := uuid.Parse(sessionID)
	// We don't have tenant ID here, using zero UUID as placeholder
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, uuid.UUID{}, &userUUID, &sessionUUID,
		helper.AuditActionSessionRevoke, helper.AuditResultSuccess,
		helper.ResourceTypeSession, &sessionUUID,
		map[string]interface{}{},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return nil
}

// internal function
func (u *authUsecase) revokeAccessToken(ctx context.Context, accessToken string) errors.BaseError {
	// Verify token to ensure it's valid before blacklisting
	userSession, err := u.hashUtilities.VerifyAccessToken(accessToken)
	if err != nil {
		return err
	}
	// Blacklist access token (15 minutes until expiry)
	err = u.tokenRepository.BlacklistAccessToken(accessToken, time.Minute*15)
	if err != nil {
		return err
	}

	// Log token revocation
	tenantUUID, _ := uuid.Parse(userSession.TenantId)
	userUUID, _ := uuid.Parse(userSession.UserId)
	sessionUUID, _ := uuid.Parse(userSession.SessionId)
	auditLog := u.auditHelper.CreateAuditLogEntry(
		ctx, tenantUUID, &userUUID, &sessionUUID,
		helper.AuditActionTokenRevoke, helper.AuditResultSuccess,
		helper.ResourceTypeToken, nil,
		map[string]interface{}{},
	)
	_ = u.auditRepository.CreateAuditLog(auditLog)

	return nil
}
