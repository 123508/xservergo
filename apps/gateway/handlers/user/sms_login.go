package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func SmsLogin(ctx context.Context, c *app.RequestContext) {
	sms := &SmsLog{}
	if err := c.Bind(sms); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.SmsLogin(ctx, &user.SmsLoginReq{
		Phone:     sms.Phone,
		Code:      sms.Code,
		Flow:      user.LoginFlowType(sms.Flow),
		RequestId: sms.RequestId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "登录成功",
		"data":    resp,
	})
}
