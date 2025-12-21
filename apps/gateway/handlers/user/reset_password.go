package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func ResetPassword(ctx context.Context, c *app.RequestContext) {
	init := &ResetPwd{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.ResetPasswordReq{
		TargetUserId:      init.TargetUserId,
		VerificationToken: init.VerifyCode,
		NewPassword:       init.NewPassword,
		RequestId:         init.RequestId,
		RequestUserId:     init.TargetUserId,
	}

	resp, err := infra.UserClient.ResetPassword(ctx, req)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	result := map[string]interface{}{
		"code": 0,
		"msg":  "修改成功",
		"data": common.ParseOperationToMap(resp),
	}

	c.JSON(http.StatusOK, result)
}
