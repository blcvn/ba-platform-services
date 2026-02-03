package entities

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	ExpiresAt    int64
}
