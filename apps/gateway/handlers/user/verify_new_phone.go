package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func VerifyNewPhone(ctx context.Context, c *app.RequestContext) {
	userId := ctx.Value("userId")

	if userId == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	requestUserId, ok := userId.(string)

	if !ok {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	req := &VBPhone{}

	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.VerifyNewPhone(ctx, &user.VerifyNewPhoneReq{
		TargetUserId:     req.UserId,
		NewPhone:         req.Phone,
		VerificationCode: req.VerifyCode,
		RequestUserId:    req.RequestId,
		RequestId:        requestUserId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "成功请求",
		"data":    resp,
	})
}
