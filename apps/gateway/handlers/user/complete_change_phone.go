package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func CompleteChangePhone(ctx context.Context, c *app.RequestContext) {
	userId := ctx.Value("userId")
	version := ctx.Value("version")

	if userId == nil || version == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	requestUserId, ok := userId.(string)
	v, ok1 := version.(uint64)

	if !ok || !ok1 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	req := &CompleteReq{}

	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.CompleteChangePhone(ctx, &user.CompleteChangePhoneReq{
		TargetUserId:     req.UserId,
		VerificationCode: req.VerifyCode,
		RequestId:        req.RequestId,
		RequestUserId:    requestUserId,
		Version:          v,
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
