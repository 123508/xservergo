package auth

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func CreatePermission(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	var permission Permission
	if err := c.BindAndValidate(&permission); err != nil {
		c.JSON(400, map[string]string{"error": "参数错误"})
		return
	}

	permissionTypeInt := auth.Permission_API
	switch permission.Type {
	case "API":
		permissionTypeInt = auth.Permission_API
	case "MENU":
		permissionTypeInt = auth.Permission_MENU
	case "BUTTON":
		permissionTypeInt = auth.Permission_BUTTON
	case "DATA":
		permissionTypeInt = auth.Permission_DATA
	case "FIELD":
		permissionTypeInt = auth.Permission_FIELD
	case "MODULE":
		permissionTypeInt = auth.Permission_MODULE
	case "FILE":
		permissionTypeInt = auth.Permission_FILE
	case "TASK":
		permissionTypeInt = auth.Permission_TASK
	}

	req := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Id:             "",
			Code:           permission.Code,
			PermissionName: permission.Name,
			Description:    permission.Description,
			ParentId:       permission.ParentID,
			Type:           permissionTypeInt,
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
		"data": Permission{
			ID:          resp.Id,
			Code:        resp.Code,
			Name:        resp.PermissionName,
			Description: resp.Description,
			ParentID:    resp.ParentId,
			Type:        permissionType(resp.Type),
			Resource:    resp.Resource,
			Method:      resp.Method,
			Status:      resp.Status,
		},
	})
}
