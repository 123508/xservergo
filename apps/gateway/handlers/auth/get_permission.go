package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func GetPermission(ctx context.Context, c *app.RequestContext) {
	permissionCode := c.Param("perm_code")
	if permissionCode == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "权限代码不能为空"})
		return
	}

	resp, err := infra.AuthClient.GetPermission(ctx, &auth.GetPermissionReq{
		PermissionCode: permissionCode,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "服务错误", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取权限成功",
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
			NeedPolicy:  resp.NeedPolicy,
		},
	})
}
