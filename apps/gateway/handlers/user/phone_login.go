package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func PhoneLogin(ctx context.Context, c *app.RequestContext) {
	init := &PhoneLog{}

	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.PhoneLoginReq{
		Phone:    init.Phone,
		Password: init.Password,
	}

	resp, err := infra.UserClient.PhoneLogin(ctx, req)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	result := map[string]interface{}{
		"code": 0,
		"msg":  "登录成功",
	}

	result["data"] = common.ParseUserInfoToMap(resp.UserInfo, map[string]interface{}{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})

	//解析成功
	c.JSON(http.StatusOK, result)
}
