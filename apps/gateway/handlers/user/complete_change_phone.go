package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func CompleteChangePhone(ctx context.Context, c *app.RequestContext) {
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

	init := &CompleteReq{}

	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.CompleteChangePhoneReq{
		TargetUserId:     init.TargetUserid,
		VerificationCode: init.VerifyCode,
		RequestId:        init.RequestId,
		RequestUserId:    requestUserId,
		Version:          v,
	}

	resp, err := infra.UserClient.CompleteChangePhone(ctx, req)

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
