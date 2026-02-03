package entities

type UserInfo struct {
	UserId      string
	TenantId    string
	Email       string
	Username    string
	Password    string
	DisplayName string
	AvatarURL   string // NEW: Avatar URL from OAuth provider
	GoogleID    string // NEW: Google OAuth subject ID
	Status      int
	Roles       []string
	Attributes  map[string]string
}

type UserData struct {
	UserInfo *UserInfo
	Token    *Token
}

type UserSession struct {
	TenantId  string
	UserId    string
	SessionId string
	RoleIds   []string
}

type Pagination struct {
	Page  int64
	Limit int64
	Total int64
}
