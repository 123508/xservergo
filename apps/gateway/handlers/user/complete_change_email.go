package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func CompleteChangeEmail(ctx context.Context, c *app.RequestContext) {
	userId := ctx.Value("userId")
	version := ctx.Value("version")

	if userId == nil || version == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	requestUserId, ok := userId.(string)
	v, ok1 := version.(uint64)

	if !ok || !ok1 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &CompleteReq{}

	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.CompleteChangeEmail(ctx, &user.CompleteChangeEmailReq{
		TargetUserId:     req.TargetUserid,
		VerificationCode: req.VerifyCode,
		RequestId:        req.RequestId,
		RequestUserId:    requestUserId,
		Version:          v,
	})

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
