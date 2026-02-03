package controllers

// NewAuthenController creates a new authenController with all required dependencies
func NewAuthenController(
	utilities iUtilities,
	transform iTransform,
	validator iValidator,
	usecase iAuthUsecase,
) *authenController {
	return &authenController{
		utilities: utilities,
		transform: transform,
		validator: validator,
		usecase:   usecase,
	}
}

func NewUserRoleController(
	utilities iUtilities,
	transform iTransform,
	validator iValidator,
	usecase iRoleUsecase,
) *userRoleController {
	return &userRoleController{
		utilities: utilities,
		transform: transform,
		validator: validator,
		usecase:   usecase,
	}
}
