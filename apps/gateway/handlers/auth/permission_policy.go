package auth

import (
	"context"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func GetPermissionPolicies(ctx context.Context, c *app.RequestContext) {
	requestUserId := ctx.Value("userId").(string)
	permissionCode := c.Param("perm_code")
	if permissionCode == "" {
		c.JSON(400, map[string]string{"error": "权限代码不能为空"})
		return
	}

	req := auth.GetPermissionPoliciesReq{
		PermissionCode: permissionCode,
		RequestUserId:  requestUserId,
	}
	resp, err := infra.AuthClient.GetPermissionPolicies(ctx, &req)
	if err != nil {
		c.JSON(500, map[string]string{"error": "获取权限关联的策略失败", "details": err.Error()})
		return
	}

	policies := make([]string, 0, len(resp.Policies))
	for _, policy := range resp.Policies {
		policies = append(policies, policy.PolicyCode)
	}

	c.JSON(200, map[string]interface{}{
		"code": 0,
		"msg":  "获取权限关联的策略成功",
		"data": map[string]interface{}{
			"policies": policies,
		},
	})
}

func AttachPermissionToPolicy(ctx context.Context, c *app.RequestContext) {
	requestUserId := ctx.Value("userId").(string)

	type AttachRequest struct {
		PermissionCode string `json:"permission_code"`
		PolicyCode     string `json:"policy_code"`
	}
	var reqBody AttachRequest
	if err := c.Bind(&reqBody); err != nil {
		c.JSON(400, map[string]string{"error": "参数错误"})
		return
	}
	if reqBody.PermissionCode == "" || reqBody.PolicyCode == "" {
		c.JSON(400, map[string]string{"error": "权限代码和策略代码不能为空"})
		return
	}

	req := auth.AttachPolicyToPermissionReq{
		PermissionCode: reqBody.PermissionCode,
		PolicyCode:     reqBody.PolicyCode,
		RequestUserId:  requestUserId,
	}
	resp, err := infra.AuthClient.AttachPolicyToPermission(ctx, &req)
	if err != nil {
		c.JSON(500, map[string]string{"error": "关联权限到策略失败", "details": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(200, map[string]interface{}{
			"code": 0,
			"msg":  "权限成功关联到策略",
		})
	} else {
		c.JSON(200, map[string]interface{}{
			"code": 1,
			"msg":  "权限关联到策略失败",
		})
	}
}

func DetachPermissionFromPolicy(ctx context.Context, c *app.RequestContext) {
	requestUserId := ctx.Value("userId").(string)

	type DetachRequest struct {
		PermissionCode string `json:"permission_code"`
		PolicyCode     string `json:"policy_code"`
	}
	var reqBody DetachRequest
	if err := c.Bind(&reqBody); err != nil {
		c.JSON(400, map[string]string{"error": "参数错误"})
		return
	}
	if reqBody.PermissionCode == "" || reqBody.PolicyCode == "" {
		c.JSON(400, map[string]string{"error": "权限代码和策略代码不能为空"})
		return
	}

	req := auth.DetachPolicyFromPermissionReq{
		PermissionCode: reqBody.PermissionCode,
		PolicyCode:     reqBody.PolicyCode,
		RequestUserId:  requestUserId,
	}
	resp, err := infra.AuthClient.DetachPolicyFromPermission(ctx, &req)
	if err != nil {
		c.JSON(500, map[string]string{"error": "解除权限与策略关联失败", "details": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(200, map[string]interface{}{
			"code": 0,
			"msg":  "权限成功与策略解除关联",
		})
	} else {
		c.JSON(200, map[string]interface{}{
			"code": 1,
			"msg":  "权限与策略解除关联失败",
		})
	}
}
