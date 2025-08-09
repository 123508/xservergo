package auth

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func UpdatePermission(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)
	permCode := c.Param("perm_code")

	var permission Permission
	if err := c.Bind(&permission); err != nil {
		c.JSON(400, map[string]string{"error": "参数错误"})
		return
	}

	req := &auth.UpdatePermissionReq{
		Permission: &auth.Permission{
			Code:           permCode,
			PermissionName: permission.Name,
			Description:    permission.Description,
			ParentId:       permission.ParentID,
			Type:           permissionTypeFromString(permission.Type),
			Resource:       permission.Resource,
			Method:         permission.Method,
			Status:         permission.Status,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.UpdatePermission(ctx, req)
	if err != nil {
		c.JSON(500, map[string]string{"error": "权限更新失败", "details": err.Error()})
		return
	}
	c.JSON(200, map[string]interface{}{
		"code": 200,
		"msg":  "权限更新成功",
		"data": Permission{
			ID:          resp.Id,
			Code:        resp.Code,
			Name:        resp.PermissionName,
			Description: resp.Description,
			ParentID:    resp.ParentId,
			Type:        permissionTypeToString(resp.Type),
			Resource:    resp.Resource,
			Method:      resp.Method,
			Status:      resp.Status,
		},
	})
}
