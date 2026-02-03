package postgres

import (
	"fmt"

	"github.com/blcvn/backend/services/auth-service/common/constants"
	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/blcvn/backend/services/auth-service/dto"
	"github.com/blcvn/backend/services/auth-service/entities"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *userRepository {
	return &userRepository{db: db}
}

func (r *userRepository) CreateUser(user *entities.RegisterPayload) (*entities.UserInfo, errors.BaseError) {
	// Parse TenantID (can be empty for BA Agent users)
	var tenantUUID *uuid.UUID
	if user.TenantId != "" {
		parsed, parseErr := uuid.Parse(user.TenantId)
		if parseErr != nil {
			return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidTenantIDFormat))
		}
		tenantUUID = &parsed
	}

	// Create DTO user
	dtoUser := &dto.User{
		ID:          uuid.New(),
		TenantID:    tenantUUID,
		Username:    user.Username,
		Password:    &user.Password, // Should already be hashed
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      dto.StatusActive,
	}

	if err := r.db.Create(dtoUser).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	// Convert to UserInfo entity
	tenantIDStr := ""
	if dtoUser.TenantID != nil {
		tenantIDStr = dtoUser.TenantID.String()
	}

	return &entities.UserInfo{
		UserId:     dtoUser.ID.String(),
		TenantId:   tenantIDStr,
		Email:      dtoUser.Email,
		Username:   dtoUser.Username,
		Roles:      []string{}, // Default empty roles
		Attributes: make(map[string]string),
	}, nil
}

func (r *userRepository) GetByUserName(username string) (*entities.UserInfo, errors.BaseError) {
	var user dto.User
	if err := r.db.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserNotFound))
		}
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	// Fetch user roles
	var userRoles []dto.UserRole
	if err := r.db.Where("user_id = ? AND status = ?", user.ID, dto.StatusActive).Find(&userRoles).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
	}

	// Extract role IDs
	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		roles = append(roles, userRole.RoleID.String())
	}

	// Helper to safely dereference pointers
	passwordStr := ""
	if user.Password != nil {
		passwordStr = *user.Password
	}
	avatarURLStr := ""
	if user.AvatarURL != nil {
		avatarURLStr = *user.AvatarURL
	}
	googleIDStr := ""
	if user.GoogleID != nil {
		googleIDStr = *user.GoogleID
	}
	tenantIDStr := ""
	if user.TenantID != nil {
		tenantIDStr = user.TenantID.String()
	}

	return &entities.UserInfo{
		UserId:      user.ID.String(),
		TenantId:    tenantIDStr,
		Email:       user.Email,
		Username:    user.Username,
		Password:    passwordStr, // Include password for verification
		DisplayName: user.DisplayName,
		AvatarURL:   avatarURLStr,
		GoogleID:    googleIDStr,
		Status:      user.Status,
		Roles:       roles,
		Attributes:  make(map[string]string),
	}, nil
}

func (r *userRepository) GetByUserID(userID string) (*entities.UserInfo, errors.BaseError) {
	userUUID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, parseErr)
	}

	var user dto.User
	if err := r.db.Where("id = ?", userUUID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserNotFound))
		}
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	// Fetch user roles
	var userRoles []dto.UserRole
	if err := r.db.Where("user_id = ? AND status = ?", user.ID, dto.StatusActive).Find(&userRoles).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
	}

	// Extract role IDs
	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		roles = append(roles, userRole.RoleID.String())
	}

	// Helper to safely dereference pointers
	avatarURLStr := ""
	if user.AvatarURL != nil {
		avatarURLStr = *user.AvatarURL
	}
	googleIDStr := ""
	if user.GoogleID != nil {
		googleIDStr = *user.GoogleID
	}
	tenantIDStr := ""
	if user.TenantID != nil {
		tenantIDStr = user.TenantID.String()
	}

	return &entities.UserInfo{
		UserId:      user.ID.String(),
		TenantId:    tenantIDStr,
		Email:       user.Email,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		AvatarURL:   avatarURLStr,
		GoogleID:    googleIDStr,
		Status:      user.Status,
		Roles:       roles,
		Attributes:  make(map[string]string),
	}, nil
}

func (r *userRepository) UpdateUserStatus(userID string, status int) (*entities.UserInfo, errors.BaseError) {
	userUUID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Update user status
	if err := r.db.Model(&dto.User{}).Where("id = ?", userUUID).Update("status", status).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToUpdateUserStatus, err))
	}

	// Fetch updated user
	return r.GetByUserID(userID)
}

func (r *userRepository) GetByEmail(email string) (*entities.UserInfo, errors.BaseError) {
	var user dto.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserNotFound))
		}
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	// Fetch user roles
	var userRoles []dto.UserRole
	if err := r.db.Where("user_id = ? AND status = ?", user.ID, dto.StatusActive).Find(&userRoles).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
	}

	// Extract role IDs
	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		roles = append(roles, userRole.RoleID.String())
	}

	// Helper to safely dereference pointers
	passwordStr := ""
	if user.Password != nil {
		passwordStr = *user.Password
	}
	avatarURLStr := ""
	if user.AvatarURL != nil {
		avatarURLStr = *user.AvatarURL
	}
	googleIDStr := ""
	if user.GoogleID != nil {
		googleIDStr = *user.GoogleID
	}
	tenantIDStr := ""
	if user.TenantID != nil {
		tenantIDStr = user.TenantID.String()
	}

	return &entities.UserInfo{
		UserId:      user.ID.String(),
		TenantId:    tenantIDStr,
		Email:       user.Email,
		Username:    user.Username,
		Password:    passwordStr,
		DisplayName: user.DisplayName,
		AvatarURL:   avatarURLStr,
		GoogleID:    googleIDStr,
		Status:      user.Status,
		Roles:       roles,
		Attributes:  make(map[string]string),
	}, nil
}

// GetByGoogleID finds a user by their Google OAuth subject ID
func (r *userRepository) GetByGoogleID(googleID string) (*entities.UserInfo, errors.BaseError) {
	var user dto.User
	if err := r.db.Where("google_id = ?", googleID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrUserNotFound))
		}
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}

	// Fetch user roles
	var userRoles []dto.UserRole
	if err := r.db.Where("user_id = ? AND status = ?", user.ID, dto.StatusActive).Find(&userRoles).Error; err != nil {
		return nil, errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf(constants.ErrFailedToQueryUserRoles, err))
	}

	// Extract role IDs
	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		roles = append(roles, userRole.RoleID.String())
	}

	// Helper to safely dereference pointers
	passwordStr := ""
	if user.Password != nil {
		passwordStr = *user.Password
	}
	avatarURLStr := ""
	if user.AvatarURL != nil {
		avatarURLStr = *user.AvatarURL
	}
	googleIDStr := ""
	if user.GoogleID != nil {
		googleIDStr = *user.GoogleID
	}
	tenantIDStr := ""
	if user.TenantID != nil {
		tenantIDStr = user.TenantID.String()
	}

	return &entities.UserInfo{
		UserId:      user.ID.String(),
		TenantId:    tenantIDStr,
		Email:       user.Email,
		Username:    user.Username,
		Password:    passwordStr,
		DisplayName: user.DisplayName,
		AvatarURL:   avatarURLStr,
		GoogleID:    googleIDStr,
		Status:      user.Status,
		Roles:       roles,
		Attributes:  make(map[string]string),
	}, nil
}

// UpdateGoogleOAuth links a Google OAuth account to an existing user
func (r *userRepository) UpdateGoogleOAuth(userID, googleID, avatarURL string) errors.BaseError {
	userUUID, parseErr := uuid.Parse(userID)
	if parseErr != nil {
		return errors.NewBaseError(errors.BAD_REQUEST, fmt.Errorf(constants.ErrInvalidUserIDFormat))
	}

	// Update google_id and avatar_url
	updates := map[string]interface{}{
		"google_id":  googleID,
		"avatar_url": avatarURL,
	}

	if err := r.db.Model(&dto.User{}).Where("id = ?", userUUID).Updates(updates).Error; err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, fmt.Errorf("failed to update google oauth: %w", err))
	}

	return nil
}
