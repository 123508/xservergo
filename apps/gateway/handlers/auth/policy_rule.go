package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func CreatePolicyRule(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	var policyRule PolicyRule
	if err := c.Bind(&policyRule); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}

	req := &auth.CreatePolicyRuleReq{
		Rule: &auth.PolicyRule{
			PolicyCode:     policyRule.PolicyCode,
			AttributeType:  policyRule.AttributeType,
			AttributeKey:   policyRule.AttributeKey,
			AttributeValue: policyRule.AttributeValue,
			Operator:       policyRule.Operator,
			Status:         policyRule.Status,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.CreatePolicyRule(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "创建策略规则失败", "details": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略规则创建成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略规则创建失败",
		})
	}
}

func UpdatePolicyRule(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	var policyRule PolicyRule
	if err := c.Bind(&policyRule); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}

	req := &auth.UpdatePolicyRuleReq{
		Rule: &auth.PolicyRule{
			Id:             policyRule.ID,
			PolicyCode:     policyRule.PolicyCode,
			AttributeType:  policyRule.AttributeType,
			AttributeKey:   policyRule.AttributeKey,
			AttributeValue: policyRule.AttributeValue,
			Operator:       policyRule.Operator,
			Status:         policyRule.Status,
		},
		RequestUserId: requestId,
	}

	resp, err := infra.AuthClient.UpdatePolicyRule(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "更新策略规则失败", "details": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略规则更新成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略规则更新失败",
		})
	}
}

func DeletePolicyRule(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)

	ruleId := c.Param("rule_id")
	if ruleId == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "策略规则ID不能为空",
		})
		return
	}

	req := &auth.DeletePolicyRuleReq{
		RuleId:        ruleId,
		RequestUserId: requestId,
	}
	resp, err := infra.AuthClient.DeletePolicyRule(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "删除策略规则失败", "details": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "策略规则删除成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 1,
			"msg":  "策略规则删除失败",
		})
	}
}

func GetPolicyRule(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)
	ruleId := c.Param("rule_id")
	if ruleId == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "策略规则ID不能为空",
		})
		return
	}

	req := &auth.GetPolicyRuleReq{
		RuleId:        ruleId,
		RequestUserId: requestId,
	}
	resp, err := infra.AuthClient.GetPolicyRule(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "获取策略规则失败", "details": err.Error()})
		return
	}

	policyRule := PolicyRule{
		ID:             resp.Rule.Id,
		PolicyCode:     resp.Rule.PolicyCode,
		AttributeType:  resp.Rule.AttributeType,
		AttributeKey:   resp.Rule.AttributeKey,
		AttributeValue: resp.Rule.AttributeValue,
		Operator:       resp.Rule.Operator,
		Status:         resp.Rule.Status,
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取策略规则成功",
		"data": policyRule,
	})
}

func ListPolicyRules(ctx context.Context, c *app.RequestContext) {
	requestId := ctx.Value("userId").(string)
	policyCode := c.Param("policy_code")
	if policyCode == "" {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "策略代码不能为空",
		})
		return
	}

	req := &auth.ListPolicyRulesReq{
		PolicyCode:    policyCode,
		RequestUserId: requestId,
	}
	resp, err := infra.AuthClient.ListPolicyRules(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "获取策略规则列表失败", "details": err.Error()})
		return
	}

	policyRules := make([]PolicyRule, 0, len(resp.Rules))
	for _, rule := range resp.Rules {
		policyRules = append(policyRules, PolicyRule{
			ID:             rule.Id,
			PolicyCode:     rule.PolicyCode,
			AttributeType:  rule.AttributeType,
			AttributeKey:   rule.AttributeKey,
			AttributeValue: rule.AttributeValue,
			Operator:       rule.Operator,
			Status:         rule.Status,
		})
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "获取策略规则列表成功",
		"data": map[string]interface{}{
			"rules": policyRules,
		},
	})
}
