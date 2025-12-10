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

type DownLoadReq struct {
	FileId    string `json:"file_id"`
	ChunkId   string `json:"chunk_id"`
	Type      uint64 `json:"type"`
	RequestId string `json:"request_id"`
}

func DownLoad(ctx context.Context, c *app.RequestContext) {

	userId := ctx.Value("userId")

	if userId == nil {
		userId = id.EmptyUUID.MarshalBase64()
	}

	requestUserId := userId.(string)

	init := &DownLoadReq{}
	err := c.Bind(init)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.DownloadReq{
		Dm: &file.DownloadMsg{
			FileId:  init.FileId,
			ChunkId: init.ChunkId,
		},
		Type:          init.Type,
		RequestId:     init.RequestId,
		RequestUserId: requestUserId,
		TargetUserId:  requestUserId,
	}

	resp, err := infra.FileClient.Download(ctx, req)

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
