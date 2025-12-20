package file

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/cloudwego/hertz/pkg/app"
)

type ListDirectoryReq struct {
	Page         uint64 `json:"page"`
	PageSize     uint64 `json:"page_size"`
	AliasId      string `json:"alias_id"`
	RootType     uint64 `json:"root_type"`
	TargetUserId string `json:"target_user_id"`
}

func ListDirectory(ctx context.Context, c *app.RequestContext) {
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
	dir := &ListDirectoryReq{}
	if err := c.Bind(dir); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.ListDirectoryReq{
		TargetUserId:  dir.TargetUserId,
		Page:          dir.Page,
		PageSize:      dir.PageSize,
		RequestUserId: requestUserId,
		AliasId:       dir.AliasId,
		RootType:      dir.RootType,
	}

	resp, err := infra.FileClient.ListDirectory(ctx, req)
	if err != nil {
		c.JSON(common.ParseGRPCError(err))
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"code": 0,
		"msg":  "请求成功",
		"data": resp,
	})
}
