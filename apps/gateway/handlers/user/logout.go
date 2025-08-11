package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func Logout(ctx context.Context, c *app.RequestContext) {

	userId := ctx.Value("userId")

	if userId == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	requestUserId, ok := userId.(string)

	if !ok {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	token := &Tokens{}
	if err := c.Bind(token); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.Logout(ctx, &user.LogoutReq{
		TargetUserId:  token.UserId,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		RequestUserId: requestUserId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "用户登出成功",
		"data": resp,
	})
}
