package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func QrLogin(ctx context.Context, c *app.RequestContext) {
	init := &QrLog{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.QrCodeLoginStatusReq{
		Ticket:    init.Ticket,
		Timeout:   init.Timeout,
		RequestId: init.RequestId,
		UserId:    init.TargetUserId,
	}

	resp, err := infra.UserClient.QrCodeLoginStatus(ctx, req)
	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "登录成功",
		"data": resp,
	})
}
