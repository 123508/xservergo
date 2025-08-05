package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func Register(ctx context.Context, c *app.RequestContext) {
	register := &RegisterModel{}

	if err := c.Bind(register); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.Register(ctx, &user.RegisterReq{
		Username: register.Username,
		Nickname: register.Nickname,
		Password: register.Password,
		Email:    register.Email,
		Phone:    register.Phone,
		Gender:   register.Gender,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	//解析成功
	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "用户注册成功",
		"data":    resp,
	})
}
