package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func StartBindEmail(ctx context.Context, c *app.RequestContext) {
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

	req := &SBEmail{}
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.StartBindEmail(ctx, &user.StartBindEmailReq{
		TargetUserId:  req.UserId,
		NewEmail:      req.Email,
		RequestUserId: requestUserId,
	})

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"code":    http.StatusOK,
		"message": "请求成功",
		"data":    resp,
	})
}
