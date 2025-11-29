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
		// 跳过预检请求，不做 token 解析，直接放行
		if string(c.Request.Method()) == http.MethodOptions {
			c.Next(ctx)
			return
		}
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
			// 尝试刷新token
			refreshTokenReq := &auth.RefreshTokenReq{
				RefreshToken: refreshToken,
			}
			refreshResp, err := infra.AuthClient.RefreshToken(ctx, refreshTokenReq)
			if err != nil {
				c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"code": http.StatusUnauthorized,
					"msg":  "令牌失效或过期，请重新登录",
				})
				c.Abort()
				return
			}
			ctx = context.WithValue(ctx, "userId", refreshResp.UserId)
			ctx = context.WithValue(ctx, "permission", refreshResp.Permissions)
			ctx = context.WithValue(ctx, "version", refreshResp.Version)
			ctx = context.WithValue(ctx, "accessToken", refreshResp.AccessToken)
			ctx = context.WithValue(ctx, "refreshToken", refreshResp.RefreshToken)
		} else {
			userId := resp.UserId
			ctx = context.WithValue(ctx, "permission", resp.Permissions)
			ctx = context.WithValue(ctx, "userId", userId)
			ctx = context.WithValue(ctx, "version", resp.Version)
		}
		c.Next(ctx)
	}
}
