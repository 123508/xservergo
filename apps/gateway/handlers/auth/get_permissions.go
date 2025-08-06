package auth

import (
	"context"
	"encoding/base64"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
	"strconv"
)

func GetPermissions(ctx context.Context, c *app.RequestContext) {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		c.JSON(400, map[string]interface{}{
			"code":   400,
			"msg":    "无效的页码",
			"detail": err.Error(),
		})
		return
	}
	pageSize, err := strconv.Atoi(c.Query("page_size"))
	if err != nil {
		c.JSON(400, map[string]interface{}{
			"code":   400,
			"msg":    "无效的每页条数",
			"detail": err.Error(),
		})
		return
	}

	listPermissionsReq := &auth.ListPermissionsReq{
		Page:          uint32(page),
		PageSize:      uint32(pageSize),
		RequestUserId: nil,
	}

	permissions, err := infra.AuthClient.ListPermissions(ctx, listPermissionsReq)
	if err != nil {
		c.JSON(500, map[string]interface{}{
			"code":   500,
			"msg":    "获取权限列表失败",
			"detail": err.Error(),
		})
		return
	}

	perms := make([]Permission, 0, len(permissions.Perms))
	for _, perm := range permissions.Perms {
		perms = append(perms, Permission{
			ID:          base64.StdEncoding.EncodeToString(perm.Id),
			Code:        perm.Code,
			Name:        perm.PermissionName,
			Description: perm.Description,
			ParentID:    string(perm.ParentId),
			Type:        permissionType(perm.Type),
			Resource:    perm.Resource,
			Method:      perm.Method,
			Status:      perm.Status,
		})
	}

	c.JSON(200, map[string]interface{}{
		"code": 200,
		"msg":  "获取权限列表成功",
		"data": map[string]interface{}{
			"perms": perms,
		},
	})
}
