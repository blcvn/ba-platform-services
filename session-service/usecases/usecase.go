package usecases

type SessionRepo interface{}

type SessionUsecase struct {
	repo SessionRepo
}

func NewSessionUsecase(repo SessionRepo) *SessionUsecase {
	return &SessionUsecase{repo: repo}
}
