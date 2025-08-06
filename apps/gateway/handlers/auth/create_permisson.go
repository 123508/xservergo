package auth

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func CreatePermission(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").([]byte)

	var permission Permission
	if err := c.BindAndValidate(&permission); err != nil {
		c.JSON(400, map[string]string{"error": "参数错误"})
		return
	}

	permissionType := auth.Permission_API
	switch permission.Type {
	case "API":
		permissionType = auth.Permission_API
	case "MENU":
		permissionType = auth.Permission_MENU
	case "BUTTON":
		permissionType = auth.Permission_BUTTON
	case "DATA":
		permissionType = auth.Permission_DATA
	case "FIELD":
		permissionType = auth.Permission_FIELD
	case "MODULE":
		permissionType = auth.Permission_MODULE
	case "FILE":
		permissionType = auth.Permission_FILE
	case "TASK":
		permissionType = auth.Permission_TASK
	}

	req := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Id:             nil,
			Code:           permission.Code,
			PermissionName: permission.Name,
			Description:    permission.Description,
			ParentId:       []byte(permission.ParentID),
			Type:           permissionType,
			Resource:       permission.Resource,
			Method:         permission.Method,
			Status:         permission.Status,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.CreatePermission(ctx, req)
	if err != nil {
		c.JSON(500, map[string]string{"error": "创建权限失败", "details": err.Error()})
		return
	}
	c.JSON(200, map[string]interface{}{
		"code": 200,
		"msg":  "权限创建成功",
		"data": resp,
	})
}
