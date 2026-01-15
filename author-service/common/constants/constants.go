package constants

// Message constants for author-service
const (
	// Success messages
	MsgCreateTenantSuccess = "Create tenant success"
	MsgUpdateTenantSuccess = "Update tenant success"
	MsgDeleteTenantSuccess = "Delete tenant success"
	MsgGetTenantSuccess    = "Get tenant success"
	MsgListTenantSuccess   = "List tenant success"

	MsgCreateRoleSuccess = "Create role success"
	MsgUpdateRoleSuccess = "Update role success"
	MsgDeleteRoleSuccess = "Delete role success"
	MsgGetRoleSuccess    = "Get role success"
	MsgListRoleSuccess   = "List role success"

	MsgCreatePermissionSuccess = "Create permission success"
	MsgUpdatePermissionSuccess = "Update permission success"
	MsgDeletePermissionSuccess = "Delete permission success"
	MsgGetPermissionSuccess    = "Get permission success"
	MsgListPermissionSuccess   = "List permission success"

	MsgAssignPermissionSuccess   = "Assign permission success"
	MsgUnassignPermissionSuccess = "Unassign permission success"
	MsgOverridePermissionSuccess = "Override permission success"

	MsgFilterSuccess = "Filter success"

	// Error messages
	MsgValidateRequestError = "Validate request error %s"

	MsgTransformTenantRequestError = "Transform tenant request error %s"
	MsgValidateTenantError         = "Validate tenant error %s"
	MsgCreateTenantError           = "Create tenant error %s"
	MsgUpdateTenantError           = "Update tenant error %s"
	MsgDeleteTenantError           = "Delete tenant error %s"
	MsgGetTenantError              = "Get tenant error %s"
	MsgListTenantError             = "List tenant error %s"
	MsgTransformTenantError        = "Transform tenant error %s"
	MsgTransformListTenantError    = "Transform list tenant error %s"
	MsgTransformPaginationError    = "Transform pagination error %s"

	MsgTransformRoleRequestError = "Transform role request error %s"
	MsgValidateRoleError         = "Validate role error %s"
	MsgCreateRoleError           = "Create role error %s"
	MsgUpdateRoleError           = "Update role error %s"
	MsgDeleteRoleError           = "Delete role error %s"
	MsgGetRoleError              = "Get role error %s"
	MsgListRoleError             = "List role error %s"
	MsgTransformRoleError        = "Transform role error %s"
	MsgTransformListRoleError    = "Transform list role error %s"

	MsgTransformPermissionRequestError = "Transform permission request error %s"
	MsgValidatePermissionError         = "Validate permission error %s"
	MsgCreatePermissionError           = "Create permission error %s"
	MsgUpdatePermissionError           = "Update permission error %s"
	MsgDeletePermissionError           = "Delete permission error %s"
	MsgGetPermissionError              = "Get permission error %s"
	MsgListPermissionError             = "List permission error %s"
	MsgTransformPermissionError        = "Transform permission error %s"
	MsgTransformListPermissionError    = "Transform list permission error %s"

	MsgTransformRolePermissionRequestError = "Transform role permission request error %s"
	MsgValidateRolePermissionError         = "Validate role permission error %s"
	MsgAssignPermissionError               = "Assign permission error %s"
	MsgUnassignPermissionError             = "Unassign permission error %s"
	MsgOverridePermissionError             = "Override permission error %s"
	MsgTransformRolePermissionError        = "Transform role permission error %s"

	MsgFilterError                  = "Filter error %s"
	MsgTransformFilterRequestError  = "Transform filter request error %s"
	MsgTransformFilterResponseError = "Transform filter response error %s"
)
