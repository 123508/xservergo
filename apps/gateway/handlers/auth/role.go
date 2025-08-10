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

// CreateRole 创建角色
func CreateRole(ctx context.Context, c *app.RequestContext) {
	req := &Role{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.CreateRole(ctx, &auth.CreateRoleReq{
		Role: &auth.Role{
			Code:        req.Code,
			RoleName:    req.Name,
			Description: req.Description,
			Status:      req.Status,
		},
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "创建角色成功",
		"data": Role{
			ID:          resp.Id,
			Code:        resp.Code,
			Name:        resp.RoleName,
			Description: resp.Description,
			Status:      resp.Status,
		},
	})
}

// UpdateRole 更新角色
func UpdateRole(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	req := &Role{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.UpdateRole(ctx, &auth.UpdateRoleReq{
		Role: &auth.Role{
			Code:        roleCode,
			RoleName:    req.Name,
			Description: req.Description,
			Status:      req.Status,
		},
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "更新角色成功",
		"data": Role{
			ID:          resp.Id,
			Code:        resp.Code,
			Name:        resp.RoleName,
			Description: resp.Description,
			Status:      resp.Status,
		},
	})
}

// DeleteRole 删除角色
func DeleteRole(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.DeleteRole(ctx, &auth.DeleteRoleReq{
		RoleCode:      roleCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "删除角色成功",
		})
	} else {
		c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"code": http.StatusInternalServerError,
			"msg":  "删除角色失败",
		})
	}
}

// GetRole 获取角色详情
func GetRole(ctx context.Context, c *app.RequestContext) {
	roleCode := c.Param("role_code")
	if roleCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "角色代码不能为空",
		})
		return
	}

	userID := ctx.Value("userId").(string)

	resp, err := infra.AuthClient.GetRole(ctx, &auth.GetRoleReq{
		RoleCode:      roleCode,
		RequestUserId: userID,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取角色成功",
		"data": Role{
			ID:          resp.Id,
			Code:        resp.Code,
			Name:        resp.RoleName,
			Description: resp.Description,
			Status:      resp.Status,
		},
	})
}

// ListRoles 获取角色列表
func ListRoles(ctx context.Context, c *app.RequestContext) {
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

	resp, err := infra.AuthClient.ListRoles(ctx, &auth.ListRolesReq{
		Page:          uint32(page),
		PageSize:      uint32(pageSize),
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
		"msg":  "获取角色列表成功",
		"data": map[string]interface{}{
			"roles": roles,
		},
	})
}
