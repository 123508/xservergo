package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// AssignRoleToUserGroup 给用户组分配角色
func AssignRoleToUserGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	type AssignRoleToUserGroupReq struct {
		RoleCode string `json:"role_code"`
	}
	req := &AssignRoleToUserGroupReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.AssignRoleToUserGroup(ctx, &auth.AssignRoleToUserGroupReq{
		UserGroupCode: groupCode,
		RoleCode:      req.RoleCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "分配角色成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "分配角色失败",
		})
	}
}

// RemoveRoleFromUserGroup 移除用户组的角色
func RemoveRoleFromUserGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	type AssignRoleToUserGroupReq struct {
		RoleCode string `json:"role_code"`
	}
	req := &AssignRoleToUserGroupReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.RemoveRoleFromUserGroup(ctx, &auth.RemoveRoleFromUserGroupReq{
		UserGroupCode: groupCode,
		RoleCode:      req.RoleCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "移除角色成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "移除角色失败",
		})
	}
}

func GetUserGroupRoles(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserGroupRoles(ctx, &auth.GetUserGroupRolesReq{
		UserGroupCode: groupCode,
		RequestUserId: userID,
	})
	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户组角色成功",
		"data": resp.Roles,
	})
}
