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
	fog := &ForgetPwd{}
	if err := c.Bind(fog); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	ForgetReq := &user.ForgotPasswordReq{
		Type: fog.Type,
	}

	if fog.Phone != "" {
		ForgetReq.Identify = &user.ForgotPasswordReq_Email{Email: fog.Phone}
	} else {
		if fog.Email != "" {
			ForgetReq.Identify = &user.ForgotPasswordReq_Email{Email: fog.Email}
		} else {
			if fog.Username != "" {
				ForgetReq.Identify = &user.ForgotPasswordReq_Username{Username: fog.Username}
			}
		}
	}

	if ForgetReq.Identify == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.ForgotPassword(ctx, ForgetReq)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "请求成功",
		"data": resp,
	})
}
