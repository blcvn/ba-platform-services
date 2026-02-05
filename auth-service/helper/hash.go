package helper

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/blcvn/backend/services/auth-service/common/configs"
	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/entities"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	jwt.RegisteredClaims
	TenantID  string   `json:"tenant_id"`
	SessionID string   `json:"session_id"`
	Type      string   `json:"type"`
	Roles     []string `json:"roles"`
}

type hashUtilities struct {
}

func NewHashUtilities() *hashUtilities {
	return &hashUtilities{}
}

// HashPassword hashes a password using bcrypt
func (h *hashUtilities) HashPassword(password string) (string, errors.BaseError) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return string(hashed), nil
}

// VerifyPassword verifies a password against a bcrypt hash
func (h *hashUtilities) VerifyPassword(hashedPassword, password string) errors.BaseError {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidPassword))
		}
		return errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return nil
}

// GenerateOpaqueToken generates a cryptographically secure random token
func (h *hashUtilities) GenerateOpaqueToken() (string, errors.BaseError) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateAccessToken generates a JWT access token with user ID and session ID
func (h *hashUtilities) GenerateAccessToken(sessionID string, userInfo *entities.UserInfo) (string, int64, errors.BaseError) {
	now := time.Now()
	accessTokenExpiry := now.Add(time.Minute * 1500) // 15 minutes

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userInfo.UserId,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
		},
		TenantID:  userInfo.TenantId,
		SessionID: sessionID,
		Type:      "access",
		Roles:     userInfo.Roles,
	})

	accessTokenStr, err := accessToken.SignedString([]byte(configs.AppConfig.JWTSecret))
	if err != nil {
		return "", 0, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	return accessTokenStr, accessTokenExpiry.Unix(), nil
}

// VerifyAccessToken verifies and parses a JWT access token
func (h *hashUtilities) VerifyAccessToken(tokenString string) (*entities.UserSession, errors.BaseError) {
	claims := &Claims{}
	token, parseErr := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf(constants.ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return []byte(configs.AppConfig.JWTSecret), nil
	})

	if parseErr != nil {
		fmt.Printf("DEBUG: JWT Parse Error: %v\n", parseErr)
		return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrInvalidToken, parseErr))
	}

	if token.Valid {
		// Verify token type
		if claims.Type != "access" {
			return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrInvalidTokenType))
		}

		// Extract user ID
		if sub := claims.Subject; sub != "" {
			if sid := claims.SessionID; sid != "" {
				return &entities.UserSession{
					UserId:    sub,
					SessionId: sid,
					TenantId:  claims.TenantID,
					RoleIds:   append([]string{}, claims.Roles...),
				}, nil
			} else {
				return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf("invalid token claims"))
			}
		} else {
			return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrInvalidTokenClaims))
		}
	}

	return nil, errors.NewBaseError(errors.UNAUTHORIZED, fmt.Errorf(constants.ErrInvalidTokenSimple))
}

// GenerateTokenPairWithRefreshToken generates an access token (JWT) with a pre-existing refresh token
// This is used when refresh token is already generated and stored in session
func (h *hashUtilities) GenerateTokenPairWithRefreshToken(sessionID, refreshToken string, userInfo *entities.UserInfo) (*entities.Token, errors.BaseError) {
	// Generate JWT access token
	accessTokenStr, expiresAt, err := h.GenerateAccessToken(sessionID, userInfo)
	if err != nil {
		return nil, err
	}

	return &entities.Token{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshToken,                          // Use the provided refresh token
		ExpiresIn:    int64(time.Minute * 15 / time.Second), // 900 seconds
		ExpiresAt:    expiresAt,
	}, nil
}
