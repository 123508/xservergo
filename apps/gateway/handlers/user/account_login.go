package user

import (
	"context"
	"fmt"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func AccountLogin(ctx context.Context, c *app.RequestContext) {

	acc := &Account{}

	if err := c.Bind(acc); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.AccountLogin(ctx, &user.AccountLoginReq{
		Username: acc.Username,
		Password: acc.Password,
	})

	fmt.Println(resp, err)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": http.StatusOK,
		"meg":  "登录成功",
		"data": resp,
	})
}
