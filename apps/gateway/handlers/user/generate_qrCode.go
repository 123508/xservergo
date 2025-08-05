package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func GenerateQrCode(ctx context.Context, c *app.RequestContext) {
	sign := &DeviceSign{}
	if err := c.Bind(sign); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}
	resp, err := infra.UserClient.GenerateQrCode(ctx, &user.GenerateQrCodeReq{
		ClientIp:  sign.ClientIp,
		UserAgent: sign.UserAgent,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "获取QR码成功",
		"data":    resp,
	})
}
