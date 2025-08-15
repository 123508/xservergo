package middleware

import (
	"context"
	"fmt"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"go.uber.org/zap"
)

func ErrorLogHandler(ctx context.Context, err error) error {

	// 获取请求信息
	ri := rpcinfo.GetRPCInfo(ctx)

	param := make([]zap.Field, 0)

	param = append(param,
		zap.String("ip", getClientIP(ri)),
		zap.String("method", ri.To().Method()),
		zap.String("path", fmt.Sprintf("%s/%s", ri.To().ServiceName(), ri.To().Method())),
		zap.Error(err),
	)

	logs.ErrorLogger.Error("", param...)

	return err
}

// 获取客户端IP
func getClientIP(ri rpcinfo.RPCInfo) string {
	remoteAddr := ri.From().Address()
	if remoteAddr == nil {
		return "unknown"
	}
	return remoteAddr.String()
}
