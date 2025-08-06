package user

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

func GetUserInfoByOthers(ctx context.Context, c *app.RequestContext) {
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

	us := &UStruct{}

	if err := c.Bind(us); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	req := &user.GetUserInfoByOthersReq{
		RequestUserId: requestUserId,
	}

	if us.Phone != "" {
		req.Identifier = &user.GetUserInfoByOthersReq_Phone{Phone: us.Phone}
	} else {
		if us.Email != "" {
			req.Identifier = &user.GetUserInfoByOthersReq_Email{Email: us.Email}
		} else {
			if us.Username != "" {
				req.Identifier = &user.GetUserInfoByOthersReq_Username{Username: us.UserId}
			}
		}
	}

	if req.Identifier == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code":    http.StatusBadRequest,
			"message": "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.GetUserInfoByOthers(ctx, req)

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
