package main

import (
	"context"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/util"
	"testing"
)

var authClient authservice.Client
var userId util.UUID

func init() {
	authClient = cli.InitAuthService()
	userId, _ = util.FromString("01981dbf-1b8a-7039-8d55-f26e2e525c26")
}

func TestAuthServiceImpl_CreatePermission(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	createPermissionReq := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Id:             nil,
			Code:           "test_permission_create_handler",
			PermissionName: "test_permission_create_handler",
			Description:    "test_permission_create_handler",
			ParentId:       nil,
			Type:           auth.Permission_API,
			Resource:       "test/resource",
			Method:         "GET",
			Status:         true,
		},
		RequestUserId: userIdBytes,
	}

	resp, err := authClient.CreatePermission(context.Background(), createPermissionReq)
	if err != nil {
		t.Fatalf("CreatePermission failed: %v", err)
	}
	if resp == nil {
		t.Fatal("CreatePermission response is nil")
	}
	t.Logf("CreatePermission response: %v", resp)
}

func TestAuthServiceImpl_UpdatePermission(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	permissionId, _ := util.FromString("01986885-58cb-7aea-9a51-2d98ebe63997")
	permissionIdBytes, _ := permissionId.Marshal()
	updatePermissionReq := &auth.UpdatePermissionReq{
		Permission: &auth.Permission{
			Id:             permissionIdBytes,
			Code:           "test_permission_create_handler_update",
			PermissionName: "test_permission_create_handler_update",
			Description:    "test_permission_create_handler_update",
			ParentId:       nil,
			Type:           auth.Permission_API,
			Resource:       "test/resource",
			Method:         "GET",
			Status:         true,
		},
		RequestUserId: userIdBytes,
	}
	resp, err := authClient.UpdatePermission(context.Background(), updatePermissionReq)
	if err != nil {
		t.Fatalf("UpdatePermission failed: %v", err)
	}
	if resp == nil {
		t.Fatal("UpdatePermission response is nil")
	}
	t.Logf("UpdatePermission response: %v", resp)
}
