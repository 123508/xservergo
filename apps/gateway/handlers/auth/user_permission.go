package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// GetUserPermissions 获取用户所有权限
func GetUserPermissions(ctx context.Context, c *app.RequestContext) {
	targetUserID := c.Param("user_id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户ID不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserPermissions(ctx, &auth.GetUserPermissionsReq{
		TargetUserId:  targetUserID,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	permissions := make([]Permission, 0, len(resp.Permissions))
	for _, p := range resp.Permissions {
		permissions = append(permissions, Permission{
			ID:          p.Id,
			Code:        p.Code,
			Name:        p.PermissionName,
			Description: p.Description,
			ParentID:    p.ParentId,
			Type:        permissionTypeToString(p.Type),
			Resource:    p.Resource,
			Method:      p.Method,
			Status:      p.Status,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户权限成功",
		"data": map[string]interface{}{
			"permissions": permissions,
		},
	})
}
