package middleware

import (
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/cors"
)

// CORSConfig 允许任何站点访问。
func CORSConfig() app.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"},
		AllowHeaders:     []string{"*"}, // 允许任意自定义请求头
		ExposeHeaders:    []string{"Content-Length", "Content-Type", "Authorization"},
		AllowCredentials: false,          // 允许任意来源访问时不能为 true
		MaxAge:           24 * time.Hour, // 预检结果缓存时间
	})
}
