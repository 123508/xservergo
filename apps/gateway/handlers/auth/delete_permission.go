package auth

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

func DeletePermission(ctx context.Context, c *app.RequestContext) {
	requestUserId := ctx.Value("userId").(string)
	permCode := c.Param("perm_code")
	if permCode == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "权限代码不能为空"})
		return
	}

	resp, err := infra.AuthClient.DeletePermission(ctx, &auth.DeletePermissionReq{
		PermissionCode: permCode,
		RequestUserId:  requestUserId,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "服务错误", "message": err.Error()})
		return
	}

	if resp.Success {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 0,
			"msg":  "删除权限成功",
		})
	} else {
		c.JSON(http.StatusOK, map[string]interface{}{
			"code": 10,
			"msg":  "删除权限失败",
		})
	}
}
