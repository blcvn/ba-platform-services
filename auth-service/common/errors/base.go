package errors

type BaseError interface {
	error
	GetCode() int
}

type baseError struct {
	code int
	err  error
}

func NewBaseError(code int, err error) *baseError {
	return &baseError{
		code: code,
		err:  err,
	}
}

func (b *baseError) Error() string {
	return b.err.Error()
}

func (b *baseError) GetCode() int {
	return b.code
}
