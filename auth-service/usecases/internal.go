package usecases

import (
	"time"

	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/blcvn/backend/services/auth-service/entities"
)

type iHashUtilities interface {
	HashPassword(password string) (string, errors.BaseError)
	VerifyPassword(hashedPassword, password string) errors.BaseError
	GenerateOpaqueToken() (string, errors.BaseError)
	VerifyAccessToken(token string) (*entities.UserSession, errors.BaseError)
	GenerateTokenPairWithRefreshToken(sessionID, refreshToken string, userInfo *entities.UserInfo) (*entities.Token, errors.BaseError)
}

type iUserRepository interface {
	CreateUser(user *entities.RegisterPayload) (*entities.UserInfo, errors.BaseError)
	GetByUserName(username string) (*entities.UserInfo, errors.BaseError)
	GetByEmail(email string) (*entities.UserInfo, errors.BaseError)
	GetByUserID(userID string) (*entities.UserInfo, errors.BaseError)
	GetByGoogleID(googleID string) (*entities.UserInfo, errors.BaseError)
	UpdateUserStatus(userID string, status int) (*entities.UserInfo, errors.BaseError)
	UpdateGoogleOAuth(userID, googleID, avatarURL string) errors.BaseError
	ListUsersByTenant(tenantId string, pagination *entities.Pagination) ([]*entities.UserInfo, *entities.Pagination, errors.BaseError)
}

type iSessionRepository interface {
	CreateSession(userID, refreshToken string, expiresAt time.Time) (string, errors.BaseError)
	GetSessionByRefreshToken(refreshToken string) (string, string, time.Time, errors.BaseError)
	GetSessionByID(sessionID string) (string, string, time.Time, errors.BaseError)
	DeleteSession(sessionID string) errors.BaseError
	DeleteAllUserSessions(userID string) errors.BaseError
}

type iTokenRepository interface {
	BlacklistAccessToken(token string, expiration time.Duration) errors.BaseError
	IsAccessTokenBlacklisted(token string) (bool, errors.BaseError)
}

type iRoleRepository interface {
	ValidateRoles(tenantId string, roleIds []string) errors.BaseError
	UnactiveRoles(userId string, roleIds []string) errors.BaseError
	UpsertRoles(userId string, roleIds []string) errors.BaseError
	UnactiveRolesExcept(userId string, exceptRoleIds []string) errors.BaseError
}

type iAuditLogRepository interface {
	CreateAuditLog(auditLog *dto.AuthAuditLog) errors.BaseError
}
