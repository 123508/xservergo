package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// GetUserGroups 获取用户所属的用户组列表
func GetUserGroups(ctx context.Context, c *app.RequestContext) {
	targetUserID := c.Param("user_id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户ID不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserGroups(ctx, &auth.GetUserGroupsReq{
		TargetUserId:  targetUserID,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户组列表成功",
		"data": map[string]interface{}{
			"user_groups": resp.UserGroups,
		},
	})
}

// AssignUserToGroup 将用户添加到用户组
func AssignUserToGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	type AssignUserToGroupReq struct {
		UserID string `json:"user_id"`
	}
	req := &AssignUserToGroupReq{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.AssignUserToGroup(ctx, &auth.AssignUserToGroupReq{
		TargetUserId:  req.UserID,
		UserGroupCode: groupCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "添加用户到组成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "添加用户到组失败",
		})
	}
}

// RemoveUserFromGroup 从用户组移除用户
func RemoveUserFromGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	type AssignUserToGroupReq struct {
		UserID string `json:"user_id"`
	}
	req := &AssignUserToGroupReq{} // 使用相同的请求体结构
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.RemoveUserFromGroup(ctx, &auth.RemoveUserFromGroupReq{
		TargetUserId:  req.UserID,
		UserGroupCode: groupCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "从组中移除用户成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "从组中移除用户失败",
		})
	}
}
