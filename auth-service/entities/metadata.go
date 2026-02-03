package entities

type Metadata struct {
	RequestId   string
	RequestTime int64
	Version     string
}

type SignatureType int32

const (
	SignatureType_NO_USE_TYPE SignatureType = 0 // Giá trị mặc định, không sử dụng
	SignatureType_J           SignatureType = 1 // Chữ ký loại J
	SignatureType_C           SignatureType = 2 // Chữ ký loại C
	SignatureType_S           SignatureType = 3 // Chữ ký loại S
)

type Signature struct {
	Type SignatureType
	S    string
	B    []byte
}

type Result struct {
	Code    int32
	Message string
}

type LoginMethod int32

const (
	LoginMethod_USERNAME_PASSWORD LoginMethod = 0
	LoginMethod_GOOGLE            LoginMethod = 1
)

type LoginPayload struct {
	TenantId string
	Username string
	Password string
	GToken   string
	Method   LoginMethod
}

type RegisterPayload struct {
	TenantId    string
	Username    string
	Password    string
	Email       string
	DisplayName string
}

type RolePayload struct {
	TenantId string
	UserId   string
	RoleIds  []string
}
