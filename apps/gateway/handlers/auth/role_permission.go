package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// GetRolePermissions 获取角色权限列表
func GetRolePermissions(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetRolePermissions(ctx, &auth.GetRolePermissionsReq{
		RoleCode:      roleCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取角色权限成功",
		"data": map[string]interface{}{
			"permissions": resp.Permissions,
		},
	})
}

// GrantPermissionToRole 给角色分配权限
func GrantPermissionToRole(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	// 解析请求参数
	type AssignPermissionToRoleReq struct {
		PermissionCode string `json:"permission_code"`
	}
	req := &AssignPermissionToRoleReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GrantPermissionToRole(ctx, &auth.GrantPermissionToRoleReq{
		RoleCode:       roleCode,
		PermissionCode: req.PermissionCode,
		RequestUserId:  userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "授权成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "授权失败",
		})
	}
}

// RevokePermissionFromRole 撤销角色权限
func RevokePermissionFromRole(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	// 解析请求参数
	type AssignPermissionToRoleReq struct {
		PermissionCode string `json:"permission_code"`
	}
	req := &AssignPermissionToRoleReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.RevokePermissionFromRole(ctx, &auth.RevokePermissionFromRoleReq{
		RoleCode:       roleCode,
		PermissionCode: req.PermissionCode,
		RequestUserId:  userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if !resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "撤销权限成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "撤销权限失败",
		})
	}
}
