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

	chunk := &FileChunkReq{}
	if err := c.Bind(chunk); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	req := &file.UploadChunkReq{
		ChunkIndex:       chunk.ChunkIndex,
		ChunkContent:     chunk.ChunkContent,
		ChunkContentHash: chunk.ChunkContentHash,
		FileId:           chunk.FileId,
		RequestUserId:    requestUserId,
		TargetUserId:     requestUserId,
		RequestId:        chunk.RequestId,
		UploadId:         chunk.UploadId,
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
