package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func QrLogin(ctx context.Context, c *app.RequestContext) {
	qrL := &QrLog{}
	if err := c.Bind(qrL); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	plaintext, err := common.DecryptAES(qrL.UserId)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.QrCodeLoginStatus(ctx, &user.QrCodeLoginStatusReq{
		Ticket:    qrL.Ticket,
		Timeout:   qrL.Timeout,
		RequestId: qrL.RequestId,
		UserId:    plaintext,
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
