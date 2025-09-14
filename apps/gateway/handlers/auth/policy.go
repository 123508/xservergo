package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func CreatePolicy(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	var policy Policy
	if err := c.Bind(&policy); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}

	req := &auth.CreatePolicyReq{
		Policy: &auth.Policy{
			PolicyCode:  policy.Code,
			PolicyName:  policy.Name,
			Description: policy.Description,
			Status:      false,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.CreatePolicy(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略创建成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略创建失败",
		})
	}
}

func UpdatePolicy(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	var policy Policy
	if err := c.Bind(&policy); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}

	req := &auth.UpdatePolicyReq{
		Policy: &auth.Policy{
			PolicyCode:  policy.Code,
			PolicyName:  policy.Name,
			Description: policy.Description,
			Status:      policy.Status,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.UpdatePolicy(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略更新成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略更新失败",
		})
	}
}

func GetPolicy(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	policyCode := c.Param("policy_code")
	if policyCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "策略代码不能为空",
		})
		return
	}

	req := &auth.GetPolicyReq{
		PolicyCode:    policyCode,
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.GetPolicy(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	policy := Policy{
		ID:          resp.Policy.Id,
		Code:        resp.Policy.PolicyCode,
		Name:        resp.Policy.PolicyName,
		Description: resp.Policy.Description,
		Status:      resp.Policy.Status,
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取策略成功",
		"data": policy,
	})
}

func DeletePolicy(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	policyCode := c.Param("policy_code")
	if policyCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "策略代码不能为空",
		})
		return
	}

	req := &auth.DeletePolicyReq{
		PolicyCode:    policyCode,
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.DeletePolicy(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略删除成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略删除失败",
		})
	}
}

func ListPolicies(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	page := parseUint32(c.DefaultQuery("page", "1"), 1)
	pageSize := parseUint32(c.DefaultQuery("page_size", "10"), 10)

	req := &auth.ListPoliciesReq{
		Page:          page,
		PageSize:      pageSize,
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.ListPolicies(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	policies := make([]Policy, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		policies = append(policies, Policy{
			ID:          p.Id,
			Code:        p.PolicyCode,
			Name:        p.PolicyName,
			Description: p.Description,
			Status:      p.Status,
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取策略列表成功",
		"data": map[string]interface{}{
			"policies": policies,
		},
	})
}
