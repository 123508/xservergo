package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func AccountLogin(ctx context.Context, c *app.RequestContext) {

	acc := &AccountLog{}

	if err := c.Bind(acc); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.AccountLogin(ctx, &user.AccountLoginReq{
		Username: acc.Username,
		Password: acc.Password,
	})

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
