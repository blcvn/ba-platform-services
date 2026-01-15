package entities

// Common entities
type Metadata struct {
	RequestId   string
	RequestTime int64
	Version     string
}

type SignatureType int32

const (
	SignatureType_NO_USE_TYPE SignatureType = 0
	SignatureType_J           SignatureType = 1
	SignatureType_C           SignatureType = 2
	SignatureType_S           SignatureType = 3
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

type Pagination struct {
	Page  int64
	Limit int64
	Total int64
}

// Domain entities

type Tenant struct {
	Id          string
	Name        string
	Description string
	Status      int
	RefId       string
	CreatedAt   int64
	UpdatedAt   int64
}

type Role struct {
	Id          string
	TenantId    string
	Name        string
	Description string
	Status      int
	CreatedAt   int64
	UpdatedAt   int64
}

type Permission struct {
	Id          string
	TenantId    string
	Name        string
	Description string
	Status      int
	Code        string
	Resource    string
	Action      string
	CreatedAt   int64
	UpdatedAt   int64
}

type RolePermission struct {
	RoleId        string
	PermissionIds []string
}

// Request entities
type FilterPayload struct {
	TenantId     string
	RoleId       string
	PermissionId string
}

type FilterResponse struct {
	Allowed bool
	Reason  string
}
