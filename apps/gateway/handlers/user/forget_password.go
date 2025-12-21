package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func ForgetPassword(ctx context.Context, c *app.RequestContext) {
	init := &ForgetPwd{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.ForgotPasswordReq{
		Type: init.Type,
	}

	ok := false //用于监听优先级

	if init.Phone != "" {
		req.Identify = &user.ForgotPasswordReq_Phone{Phone: init.Phone}
		ok = true
	}

	if !ok && init.Username != "" {
		req.Identify = &user.ForgotPasswordReq_Username{Username: init.Username}
		ok = true
	}

	if !ok && init.Email != "" {
		req.Identify = &user.ForgotPasswordReq_Email{Email: init.Email}
		ok = true
	}

	if !ok || req.Identify == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.ForgotPassword(ctx, req)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	result := map[string]interface{}{
		"code": 0,
		"msg":  "请求成功",
		"data": common.ParseOperationToMap(resp),
	}

	c.JSON(http.StatusOK, result)
}
