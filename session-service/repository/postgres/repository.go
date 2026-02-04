package postgres

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	// Ensure the table is migrated
	db.AutoMigrate(&Session{})
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Save(ctx context.Context, s *Session) (*Session, error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	if err := r.db.WithContext(ctx).Create(s).Error; err != nil {
		return nil, err
	}
	return s, nil
}

func (r *SessionRepository) Update(ctx context.Context, s *Session) (*Session, error) {
	if err := r.db.WithContext(ctx).Model(&Session{}).Where("id = ?", s.ID).Updates(s).Error; err != nil {
		return nil, err
	}
	// Fetch updated record to return fresh data
	var updated Session
	if err := r.db.WithContext(ctx).First(&updated, "id = ?", s.ID).Error; err != nil {
		return nil, err
	}
	return &updated, nil
}

func (r *SessionRepository) Get(ctx context.Context, id string) (*Session, error) {
	var s Session
	if err := r.db.WithContext(ctx).First(&s, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SessionRepository) GetByProject(ctx context.Context, projectID string) (*Session, error) {
	var s Session
	if err := r.db.WithContext(ctx).Where("project_id = ? AND status = ?", projectID, "active").Order("created_at desc").First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}
