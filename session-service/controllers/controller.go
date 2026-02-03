package controllers

import (
	"github.com/blcvn/backend/services/session-service/helper"
	"github.com/blcvn/backend/services/session-service/usecases"
	pb "github.com/blcvn/kratos-proto/go/session"
)

type SessionController struct {
	pb.UnimplementedSessionServiceServer
	uc        *usecases.SessionUsecase
	transform *helper.Transform
}

func NewSessionController(uc *usecases.SessionUsecase, transform *helper.Transform) *SessionController {
	return &SessionController{uc: uc, transform: transform}
}
