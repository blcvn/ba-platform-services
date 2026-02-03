package controllers

import pb "github.com/blcvn/kratos-proto/go/author"

func buildTenantResponse(meta *pb.Metadata, sig *pb.Signature, code pb.ResultCode, msg string, tenant *pb.TenantPayload) *pb.TenantResponse {
	return &pb.TenantResponse{
		Metadata:  meta,
		Signature: sig,
		Result: &pb.Result{
			Code:    code,
			Message: msg,
		},
		Payload: tenant,
	}
}

func buildRoleResponse(meta *pb.Metadata, sig *pb.Signature, code pb.ResultCode, msg string, role *pb.RolePayload) *pb.RoleResponse {
	return &pb.RoleResponse{
		Metadata:  meta,
		Signature: sig,
		Result: &pb.Result{
			Code:    code,
			Message: msg,
		},
		Payload: role,
	}
}

func buildPermissionResponse(meta *pb.Metadata, sig *pb.Signature, code pb.ResultCode, msg string, permission *pb.PermissionPayload) *pb.PermissionResponse {
	return &pb.PermissionResponse{
		Metadata:  meta,
		Signature: sig,
		Result: &pb.Result{
			Code:    code,
			Message: msg,
		},
		Payload: permission,
	}
}

func buildRolePermissionResponse(meta *pb.Metadata, sig *pb.Signature, code pb.ResultCode, msg string) *pb.RolePermissionResponse {
	return &pb.RolePermissionResponse{
		Metadata:  meta,
		Signature: sig,
		Result: &pb.Result{
			Code:    code,
			Message: msg,
		},
	}
}
