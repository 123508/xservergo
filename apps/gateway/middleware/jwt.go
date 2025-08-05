package middleware

import (
	"context"
	"github.com/123508/xservergo/apps/gateway/infra"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/cloudwego/hertz/pkg/app"
	"net/http"
)

// ParseToken 解析token
func ParseToken() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		token := string(c.Cookie("access_token"))

		// 解析jwt
		resp, err := infra.AuthCList.VerifyToken(ctx, &auth.VerifyTokenReq{
			AccessToken: token,
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
		c.Next(context.WithValue(ctx, "userId", userId))
		c.Next(context.WithValue(ctx, "version", resp.Version))
	}
}
