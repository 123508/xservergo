package middleware

import (
	"context"
	"time"

	"github.com/123508/xservergo/pkg/logs"
	"github.com/cloudwego/hertz/pkg/app"
	"go.uber.org/zap"
)

func RequestLogger() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// 在请求处理前记录开始日志
		start := time.Now()
		logRequest(c, "开始处理请求")

		// 继续处理请求
		c.Next(ctx)

		// 请求完成后记录结束日志
		duration := time.Since(start)
		logResponse(c, "请求处理完成", duration)
	}
}

// 记录请求开始日志
func logRequest(c *app.RequestContext, message string) {

	param := make([]zap.Field, 0)

	param = append(param, zap.String("ip", getClientIP(c)),
		zap.String("method", string(c.Method())),
		zap.String("path", string(c.Path())))

	logs.AccessLogger.Info(message, param...)
}

// 记录请求结束日志
func logResponse(c *app.RequestContext, message string, duration time.Duration) {

	param := make([]zap.Field, 0)

	param = append(param, zap.String("ip", getClientIP(c)),
		zap.String("method", string(c.Method())),
		zap.String("path", string(c.Path())),
		zap.Duration("duration", duration),
		zap.Int("status", c.Response.StatusCode()))

	logs.AccessLogger.Info(message, param...)
}

// 获取客户端IP
func getClientIP(c *app.RequestContext) string {
	ip := c.ClientIP()
	if ip == "" {
		return "unknown"
	}
	return ip
}
