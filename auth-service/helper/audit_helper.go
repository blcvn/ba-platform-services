package helper

import (
	"context"
	"net"
	"time"

	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/google/uuid"
)

// Audit action constants
const (
	AuditActionRegister      = "REGISTER"
	AuditActionLogin         = "LOGIN"
	AuditActionLoginGoogle   = "LOGIN_GOOGLE"
	AuditActionLogout        = "LOGOUT"
	AuditActionTokenRefresh  = "TOKEN_REFRESH"
	AuditActionTokenRevoke   = "TOKEN_REVOKE"
	AuditActionSessionRevoke = "SESSION_REVOKE"
	AuditActionVerifyToken   = "VERIFY_TOKEN"
)

// Audit result constants
const (
	AuditResultSuccess = "success"
	AuditResultFailure = "failure"
	AuditResultError   = "error"
)

// Resource type constants
const (
	ResourceTypeUser    = "user"
	ResourceTypeSession = "session"
	ResourceTypeToken   = "token"
)

type AuditHelper struct {
	utilities iUtilities
}

type iUtilities interface {
	GetClientIP(ctx context.Context) string
	GetUserAgent(ctx context.Context) string
}

func NewAuditHelper(utilities iUtilities) *AuditHelper {
	return &AuditHelper{utilities: utilities}
}

// CreateAuditLogEntry builds an audit log entry from context and event data
func (h *AuditHelper) CreateAuditLogEntry(
	ctx context.Context,
	tenantID uuid.UUID,
	userID *uuid.UUID,
	sessionID *uuid.UUID,
	action string,
	result string,
	resourceType string,
	resourceID *uuid.UUID,
	metadata map[string]interface{},
) *dto.AuthAuditLog {
	// Extract client information from context
	ipStr := h.utilities.GetClientIP(ctx)
	var ipAddr net.IP
	if ipStr != "" {
		ipAddr = net.ParseIP(ipStr)
	}

	userAgent := h.utilities.GetUserAgent(ctx)

	return &dto.AuthAuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		SessionID:    sessionID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Result:       result,
		Metadata:     metadata,
		Status:       dto.StatusActive,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}
