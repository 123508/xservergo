package middleware

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
)

// RefreshToken 更新token
func RefreshToken() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Next(ctx)
		accessToken, ok1 := ctx.Value("accessToken").(string)
		refreshToken, ok2 := ctx.Value("refreshToken").(string)
		if ok1 && ok2 && accessToken != "" && refreshToken != "" {
			c.Header("access_token", accessToken)
			c.Header("refresh_token", refreshToken)
		}
	}
}
