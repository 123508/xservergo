package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/config"
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
			if resp.Ttl < int64(config.Conf.Jwt.AdminSuv) {
				// 如果token的有效期小于一定时间，则需要刷新token
				refreshTokenReq := &auth.RefreshTokenReq{
					RefreshToken: refreshToken,
				}
				refreshResp, err := infra.AuthClient.RefreshToken(ctx, refreshTokenReq)
				if err != nil {
					c.JSON(http.StatusUnauthorized, map[string]interface{}{
						"code":   http.StatusUnauthorized,
						"msg":    "令牌已过期，请重新登录",
						"detail": err.Error(),
					})
					c.Abort()
					return
				}
				ctx = context.WithValue(ctx, "accessToken", refreshResp.AccessToken)
				ctx = context.WithValue(ctx, "refreshToken", refreshResp.RefreshToken)
			}

			userId := resp.UserId
			ctx = context.WithValue(ctx, "permission", resp.Permissions)
			ctx = context.WithValue(ctx, "userId", userId)
			ctx = context.WithValue(ctx, "version", resp.Version)
		}
		c.Next(ctx)
	}
}
