package file

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/common"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/cloudwego/hertz/pkg/app"
)

type InitUploadReq struct {
	FileList []FileItem `json:"file_list"`
}

func InitUpload(ctx context.Context, c *app.RequestContext) {

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

	init := &InitUploadReq{}
	if err := c.Bind(init); err != nil {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"code": http.StatusBadRequest,
			"msg":  "请求参数错误",
		})
		return
	}

	list := make([]*file.FileItem, len(init.FileList))

	for i := range init.FileList {
		item := init.FileList[i]
		list[i] = &file.FileItem{
			FileContentHash: item.FileContentHash,
			FileSize:        item.FileSize,
			FileName:        item.FileName,
			Total:           item.Total,
		}
	}

	req := &file.InitUploadReq{
		FileList:      list,
		RequestUserId: requestUserId,
		TargetUserId:  requestUserId,
	}

	resp, err := infra.FileClient.InitUpload(ctx, req)

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
