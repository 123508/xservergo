package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func ResetPassword(ctx context.Context, c *app.RequestContext) {
	rst := &ResetPwd{}
	if err := c.Bind(rst); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.ResetPassword(ctx, &user.ResetPasswordReq{
		TargetUserId:      rst.TargetUserId,
		VerificationToken: rst.VerifyCode,
		NewPassword:       rst.NewPassword,
		RequestId:         rst.RequestId,
		RequestUserId:     rst.TargetUserId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "修改成功",
		"data":    resp,
	})
}
