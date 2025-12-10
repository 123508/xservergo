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

type DirectDownLoadStruct struct {
	AliasID string `json:"alias_id"`
}

func DirectDownLoad(ctx context.Context, c *app.RequestContext) {

	userId := ctx.Value("userId")

	if userId == nil {
		userId = id.EmptyUUID.MarshalBase64()
	}

	requestUserId := userId.(string)

	init := &DirectDownLoadStruct{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.DirectDownloadFileReq{
		AliasId:       init.AliasID,
		RequestUserId: requestUserId,
		TargetUserId:  requestUserId,
	}

	resp, err := infra.FileClient.DirectDownload(ctx, req)

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
