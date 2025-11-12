package user

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/user"
	"github.com/cloudwego/hertz/pkg/app"
)

func GetUserInfoByOthers(ctx context.Context, c *app.RequestContext) {
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

	us := &UStruct{}

	if err := c.Bind(us); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &user.GetUserInfoByOthersReq{
		RequestUserId: requestUserId,
	}

	execute := false

	if us.Phone != "" {
		req.Identifier = &user.GetUserInfoByOthersReq_Phone{Phone: us.Phone}
		execute = true
	}
	if !execute && us.Email != "" {
		req.Identifier = &user.GetUserInfoByOthersReq_Email{Email: us.Email}
		execute = true
	}
	if !execute && us.Username != "" {
		req.Identifier = &user.GetUserInfoByOthersReq_Username{Username: us.UserId}
		execute = true
	}

	if !execute && req.Identifier == nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	resp, err := infra.UserClient.GetUserInfoByOthers(ctx, req)

	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}

	result := map[string]interface{}{
		"code": 0,
		"msg":  "获取成功",
		"data": common.ParseUserInfoToMap(resp.UserInfo, common.ParseOperationToMap(resp.Result)),
	}

	c.JSON(http.StatusOK, result)
}
