package usecases

import "github.com/blcvn/backend/services/auth-service/helper"

// NewAuthUsecase creates a new authUsecase with all required dependencies
func NewAuthUsecase(
	userRepository iUserRepository,
	sessionRepository iSessionRepository,
	tokenRepository iTokenRepository,
	auditRepository iAuditLogRepository,
	hashUtilities iHashUtilities,
	auditHelper *helper.AuditHelper,
) *authUsecase {
	return &authUsecase{
		userRepository:    userRepository,
		sessionRepository: sessionRepository,
		tokenRepository:   tokenRepository,
		auditRepository:   auditRepository,
		hashUtilities:     hashUtilities,
		auditHelper:       auditHelper,
	}
}
