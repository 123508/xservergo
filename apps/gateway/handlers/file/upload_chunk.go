package file

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/cloudwego/hertz/pkg/app"
)

type FileChunkReq struct {
	ChunkIndex       uint64 `json:"chunk_index"`
	ChunkContent     []byte `json:"chunk_content"`
	ChunkContentHash string `json:"chunk_content_hash"`
	FileId           string `json:"file_id"`
	RequestId        string `json:"request_id"`
	UploadId         string `json:"upload_id"`
	TargetUserId     string `json:"target_user_id"`
}

func UploadChunk(ctx context.Context, c *app.RequestContext) {

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

	init := &FileChunkReq{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.UploadChunkReq{
		ChunkIndex:       init.ChunkIndex,
		ChunkContent:     init.ChunkContent,
		ChunkContentHash: init.ChunkContentHash,
		FileId:           init.FileId,
		RequestUserId:    requestUserId,
		TargetUserId:     init.TargetUserId,
		RequestId:        init.RequestId,
		UploadId:         init.UploadId,
	}

	resp, err := infra.FileClient.UploadChunk(ctx, req)

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
