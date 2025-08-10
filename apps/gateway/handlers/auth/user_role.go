package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// GetUserRoles 获取用户角色列表
func GetUserRoles(ctx context.Context, c *app.RequestContext) {
	targetUserID := c.Param("user_id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户ID不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserRoles(ctx, &auth.GetUserRolesReq{
		TargetUserId:  targetUserID,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	roles := make([]Role, 0, len(resp.Roles))
	for _, role := range resp.Roles {
		roles = append(roles, Role{
			ID:          role.Id,
			Code:        role.Code,
			Name:        role.RoleName,
			Description: role.Description,
			Status:      role.Status,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户角色成功",
		"data": map[string]interface{}{
			"roles": roles,
		},
	})
}

// AssignRoleToUser 给用户分配角色
func AssignRoleToUser(ctx context.Context, c *app.RequestContext) {
	targetUserID := c.Param("user_id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户ID不能为空",
		})
		return
	}

	type AssignRoleToUserReq struct {
		RoleCode string `json:"role_code"`
	}
	req := &AssignRoleToUserReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.AssignRoleToUser(ctx, &auth.AssignRoleToUserReq{
		TargetUserId:  targetUserID,
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

// RemoveRoleFromUser 移除用户角色
func RemoveRoleFromUser(ctx context.Context, c *app.RequestContext) {
	targetUserID := c.Param("user_id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户ID不能为空",
		})
		return
	}

	type AssignRoleToUserReq struct {
		RoleCode string `json:"role_code"`
	}
	req := &AssignRoleToUserReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.RemoveRoleFromUser(ctx, &auth.RemoveRoleFromUserReq{
		TargetUserId:  targetUserID,
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
