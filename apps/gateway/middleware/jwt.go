package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
)

// ParseToken 解析token
func ParseToken() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		Authorization := strings.Split(c.Request.Header.Get("Authorization"), " ")
		accessToken := ""
		if len(Authorization) > 1 {
			accessToken = Authorization[1]
		}
		refreshToken := c.Request.Header.Get("RefreshToken")

		// 解析jwt
		resp, err := infra.AuthClient.VerifyToken(ctx, &auth.VerifyTokenReq{
			AccessToken: accessToken,
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, map[string]interface{}{
				"code": http.StatusUnauthorized,
				"msg":  "请先登录",
			})
			c.Abort()
			return
		}

		userId := resp.UserId
		ctx = context.WithValue(ctx, "permission", resp.Permissions)
		ctx = context.WithValue(ctx, "userId", userId)
		ctx = context.WithValue(ctx, "refreshToken", refreshToken)
		ctx = context.WithValue(ctx, "version", resp.Version)
		c.Next(ctx)
	}
}
