package postgres

import (
	"time"

	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type sessionRepo struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *sessionRepo {
	return &sessionRepo{db: db}
}

func (r *sessionRepo) CreateSession(userID, refreshToken string, expiresAt time.Time) (sessionID string, err errors.BaseError) {
	// Parse userID to UUID
	userUUID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return "", errors.NewBaseError(errors.BAD_REQUEST, parseErr)
	}

	session := &dto.UserSession{
		UserID:       userUUID,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}

	if dbErr := r.db.Create(session).Error; dbErr != nil {
		return "", errors.NewBaseError(errors.INTERNAL_ERROR, dbErr)
	}

	return session.ID.String(), nil
}

func (r *sessionRepo) GetSessionByRefreshToken(refreshToken string) (sessionID, userID string, expiresAt time.Time, err errors.BaseError) {
	var session dto.UserSession
	if dbErr := r.db.Where("refresh_token = ?", refreshToken).First(&session).Error; dbErr != nil {
		if dbErr == gorm.ErrRecordNotFound {
			return "", "", time.Time{}, errors.NewBaseError(errors.BAD_REQUEST, dbErr)
		}
		return "", "", time.Time{}, errors.NewBaseError(errors.INTERNAL_ERROR, dbErr)
	}

	return session.ID.String(), session.UserID.String(), session.ExpiresAt, nil
}

func (r *sessionRepo) GetSessionByID(sessionID string) (userID string, refreshToken string, expiresAt time.Time, err errors.BaseError) {
	// Parse sessionID to UUID
	sessionUUID, parseErr := uuid.Parse(sessionID)
	if parseErr != nil {
		return "", "", time.Time{}, errors.NewBaseError(errors.BAD_REQUEST, parseErr)
	}

	var session dto.UserSession
	if dbErr := r.db.Where("id = ?", sessionUUID).First(&session).Error; dbErr != nil {
		if dbErr == gorm.ErrRecordNotFound {
			return "", "", time.Time{}, errors.NewBaseError(errors.BAD_REQUEST, dbErr)
		}
		return "", "", time.Time{}, errors.NewBaseError(errors.INTERNAL_ERROR, dbErr)
	}

	return session.UserID.String(), session.RefreshToken, session.ExpiresAt, nil
}

func (r *sessionRepo) DeleteSession(sessionID string) errors.BaseError {
	// Parse sessionID to UUID
	sessionUUID, parseErr := uuid.Parse(sessionID)
	if parseErr != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, parseErr)
	}

	if dbErr := r.db.Delete(&dto.UserSession{}, "id = ?", sessionUUID).Error; dbErr != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, dbErr)
	}

	return nil
}

func (r *sessionRepo) DeleteAllUserSessions(userID string) errors.BaseError {
	// Parse userID to UUID
	userUUID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, parseErr)
	}

	if dbErr := r.db.Delete(&dto.UserSession{}, "user_id = ?", userUUID).Error; dbErr != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, dbErr)
	}

	return nil
}
