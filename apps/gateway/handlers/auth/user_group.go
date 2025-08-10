package auth

import (
	"context"
	"net/http"
	"strconv"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// CreateUserGroup 创建用户组
func CreateUserGroup(ctx context.Context, c *app.RequestContext) {
	req := &UserGroup{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.CreateUserGroup(ctx, &auth.CreateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      req.Code,
			GroupName: req.Name,
			Status:    req.Status,
			ParentId:  req.ParentID,
		},
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "创建用户组成功",
		"data": UserGroup{
			ID:       resp.Id,
			Name:     resp.GroupName,
			Code:     resp.Code,
			Status:   resp.Status,
			ParentID: resp.ParentId,
		},
	})
}

// UpdateUserGroup 更新用户组
func UpdateUserGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	req := &UserGroup{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.UpdateUserGroup(ctx, &auth.UpdateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      groupCode,
			GroupName: req.Name,
			Status:    req.Status,
			ParentId:  req.ParentID,
		},
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "更新用户组成功",
		"data": UserGroup{
			ID:       resp.Id,
			Name:     resp.GroupName,
			Code:     resp.Code,
			Status:   resp.Status,
			ParentID: resp.ParentId,
		},
	})
}

// DeleteUserGroup 删除用户组
func DeleteUserGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.DeleteUserGroup(ctx, &auth.DeleteUserGroupReq{
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
			"msg":  "删除用户组成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "删除用户组失败",
		})
	}
}

// GetUserGroup 获取用户组详情
func GetUserGroup(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserGroup(ctx, &auth.GetUserGroupReq{
		UserGroupCode: groupCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户组成功",
		"data": UserGroup{
			ID:       resp.Id,
			Name:     resp.GroupName,
			Code:     resp.Code,
			Status:   resp.Status,
			ParentID: resp.ParentId,
		},
	})
}

// ListUserGroups 获取用户组列表
func ListUserGroups(ctx context.Context, c *app.RequestContext) {
	pageStr := c.Query("page")
	pageSizeStr := c.Query("page_size")

	page, err := strconv.ParseUint(pageStr, 10, 32)
	if err != nil {
		page = 1
	}

	pageSize, err := strconv.ParseUint(pageSizeStr, 10, 32)
	if err != nil {
		pageSize = 10
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.ListUserGroups(ctx, &auth.ListUserGroupsReq{
		Page:          uint32(page),
		PageSize:      uint32(pageSize),
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	userGroups := make([]UserGroup, 0, len(resp.UserGroups))
	for _, ug := range resp.UserGroups {
		userGroups = append(userGroups, UserGroup{
			ID:       ug.Id,
			Name:     ug.GroupName,
			Code:     ug.Code,
			Status:   ug.Status,
			ParentID: ug.ParentId,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户组列表成功",
		"data": map[string]interface{}{
			"user_groups": userGroups,
		},
	})
}

// GetUserGroupMembers 获取用户组成员
func GetUserGroupMembers(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserGroupMembers(ctx, &auth.GetUserGroupMembersReq{
		UserGroupCode: groupCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	users := make([]User, 0, len(resp.Users))
	for _, u := range resp.Users {
		users = append(users, User{
			ID:       u.UserId,
			Username: u.Username,
			Nickname: u.Nickname,
			Email:    u.Email,
			Phone:    u.Phone,
			Gender:   u.Gender,
			Avatar:   u.Avatar,
			Status:   u.Status,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取用户组成员成功",
		"data": map[string]interface{}{
			"users": users,
		},
	})
}

// GetUserGroupPermissions 获取用户组权限
func GetUserGroupPermissions(ctx context.Context, c *app.RequestContext) {
	groupCode := c.Param("group_code")
	if groupCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "用户组代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetUserGroupPermissions(ctx, &auth.GetUserGroupPermissionsReq{
		UserGroupCode: groupCode,
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
		"msg":  "获取用户组权限成功",
		"data": map[string]interface{}{
			"permissions": permissions,
		},
	})
}
