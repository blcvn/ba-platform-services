package usecases

import (
	"context"
	"time"

	"github.com/blcvn/backend/services/session-service/repository/postgres"
)

type SessionRepo interface {
	Save(ctx context.Context, s *postgres.Session) (*postgres.Session, error)
	Update(ctx context.Context, s *postgres.Session) (*postgres.Session, error)
	Get(ctx context.Context, id string) (*postgres.Session, error)
	GetByProject(ctx context.Context, projectID string) (*postgres.Session, error)
}

type SessionUsecase struct {
	repo SessionRepo
}

func NewSessionUsecase(repo SessionRepo) *SessionUsecase {
	return &SessionUsecase{repo: repo}
}

func (uc *SessionUsecase) Create(ctx context.Context, projectID string) (*postgres.Session, error) {
	s := &postgres.Session{
		ProjectID: projectID,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return uc.repo.Save(ctx, s)
}

func (uc *SessionUsecase) Update(ctx context.Context, s *postgres.Session) (*postgres.Session, error) {
	s.UpdatedAt = time.Now()
	return uc.repo.Update(ctx, s)
}

func (uc *SessionUsecase) Get(ctx context.Context, id string) (*postgres.Session, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *SessionUsecase) GetByProject(ctx context.Context, projectID string) (*postgres.Session, error) {
	return uc.repo.GetByProject(ctx, projectID)
}
