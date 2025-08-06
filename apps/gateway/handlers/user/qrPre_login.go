package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func QrPreLogin(ctx context.Context, c *app.RequestContext) {
	query := &QrQuery{}
	if err := c.Bind(query); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.QrCodePreLoginStatus(ctx, &user.QrCodePreLoginStatusReq{
		Ticket:    query.Ticket,
		Timeout:   query.Timeout,
		RequestId: query.RequestId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "轮询成功",
		"data": map[string]interface{}{
			"user_id":    resp.UserId,
			"request_id": query.RequestId,
		},
	})
}
