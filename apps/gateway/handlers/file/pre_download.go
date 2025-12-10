package file

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/cloudwego/hertz/pkg/app"
)

type PreDownloadReq struct {
	AliasId string `json:"alias_id"`
}

func PreDownload(ctx context.Context, c *app.RequestContext) {
	userId := ctx.Value("userId")

	if userId == nil {
		userId = id.EmptyUUID.MarshalBase64()
	}

	requestUserId := userId.(string)

	init := &PreDownloadReq{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.PreDownLoadReq{
		AliasId:       init.AliasId,
		RequestUserId: requestUserId,
		TargetUserId:  requestUserId,
	}

	resp, err := infra.FileClient.PreDownLoad(ctx, req)

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
