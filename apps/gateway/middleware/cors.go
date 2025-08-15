package middleware

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/cors"
	"time"
)

func CORSConfig() app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		cors.New(cors.Config{
			AllowOrigins:     []string{"*"}, // 允许所有来源
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour, // 预检请求缓存时间
		})
	}
}
