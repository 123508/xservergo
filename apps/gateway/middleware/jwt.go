package middleware

import (
	"context"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/cloudwego/hertz/pkg/app"
)

// ParseToken 解析token
func ParseToken() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		token := string(c.Cookie("token"))

		authClient := cli.InitAuthService()
		// 解析jwt
		resp, err := authClient.VerifyToken(ctx, &auth.VerifyTokenReq{
			AccessToken: token,
		})
		if err != nil {
			c.JSON(401, map[string]interface{}{
				"error": "请先登录",
			})
			c.Abort()
			return
		}
		userId := resp.UserId
		ctx = context.WithValue(ctx, "permission", resp.Permissions)
		c.Next(context.WithValue(ctx, "userId", userId))
	}
}
