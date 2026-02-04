package controllers

import (
	"context"
	"time"

	"github.com/blcvn/backend/services/session-service/helper"
	"github.com/blcvn/backend/services/session-service/repository/postgres"
	"github.com/blcvn/backend/services/session-service/usecases"
	pb "github.com/blcvn/kratos-proto/go/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SessionController struct {
	pb.UnimplementedSessionServiceServer
	uc        *usecases.SessionUsecase
	transform *helper.Transform
}

func NewSessionController(uc *usecases.SessionUsecase, transform *helper.Transform) *SessionController {
	return &SessionController{uc: uc, transform: transform}
}

func (c *SessionController) CreateSession(ctx context.Context, req *pb.CreateSessionRequest) (*pb.SessionReply, error) {
	if req.Payload == nil || req.Payload.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "Project ID is required")
	}

	result, err := c.uc.Create(ctx, req.Payload.ProjectId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.SessionReply{
		Result:  &pb.Result{Code: pb.ResultCode_SUCCESS, Message: "Session created successfully"},
		Payload: convertToProto(result),
	}, nil
}

func (c *SessionController) UpdateSession(ctx context.Context, req *pb.UpdateSessionRequest) (*pb.SessionReply, error) {
	if req.Payload == nil || req.Payload.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "Session ID is required")
	}

	// Fetch existing session first to ensure it exists and get its metadata
	s, err := c.uc.Get(ctx, req.Payload.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Session not found")
	}

	// Dynamic update based on payload
	if req.Payload.CurrentFeatureId != "" {
		s.CurrentFeatureID = &req.Payload.CurrentFeatureId
	}
	if req.Payload.Status != "" {
		s.Status = req.Payload.Status
	}

	result, err := c.uc.Update(ctx, s)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.SessionReply{
		Result:  &pb.Result{Code: pb.ResultCode_SUCCESS, Message: "Session updated successfully"},
		Payload: convertToProto(result),
	}, nil
}

func (c *SessionController) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.SessionReply, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "Session ID is required")
	}

	result, err := c.uc.Get(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Session not found")
	}

	return &pb.SessionReply{
		Result:  &pb.Result{Code: pb.ResultCode_SUCCESS, Message: "Session found"},
		Payload: convertToProto(result),
	}, nil
}

func (c *SessionController) GetSessionByProject(ctx context.Context, req *pb.GetSessionByProjectRequest) (*pb.SessionReply, error) {
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "Project ID is required")
	}

	result, err := c.uc.GetByProject(ctx, req.ProjectId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Active session not found for this project")
	}

	return &pb.SessionReply{
		Result:  &pb.Result{Code: pb.ResultCode_SUCCESS, Message: "Active session found"},
		Payload: convertToProto(result),
	}, nil
}

func convertToProto(s *postgres.Session) *pb.Session {
	res := &pb.Session{
		Id:        s.ID,
		ProjectId: s.ProjectID,
		Status:    s.Status,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		UpdatedAt: s.UpdatedAt.Format(time.RFC3339),
	}
	if s.CurrentFeatureID != nil {
		res.CurrentFeatureId = *s.CurrentFeatureID
	}
	return res
}
