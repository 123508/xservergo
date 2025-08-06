package auth

import (
	"context"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func GetPermission(ctx context.Context, c *app.RequestContext) {
	permissionCode := c.Param("perm_code")
	if permissionCode == "" {
		c.JSON(400, map[string]string{"error": "权限代码不能为空"})
		return
	}

	resp, err := infra.AuthClient.GetPermission(ctx, &auth.GetPermissionReq{
		PermissionCode: permissionCode,
	})
	if err != nil {
		c.JSON(500, map[string]string{"error": "服务错误", "message": err.Error()})
		return
	}
	c.JSON(200, map[string]interface{}{
		"code": 200,
		"msg":  "获取权限成功",
		"data": resp,
	})
}
