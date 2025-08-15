package middleware

import (
	"context"
	"fmt"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/cloudwego/kitex/pkg/endpoint"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"go.uber.org/zap"
)

func AccessLogHandler(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, req, resp interface{}) (err error) {

		err = next(ctx, req, resp)

		if err != nil {
			return err
		}
		// 获取请求信息
		ri := rpcinfo.GetRPCInfo(ctx)

		param := make([]zap.Field, 0)

		param = append(param,
			zap.String("ip", getClientIP(ri)),
			zap.String("method", ri.To().Method()),
			zap.String("path", fmt.Sprintf("%s/%s", ri.To().ServiceName(), ri.To().Method())),
		)

		logs.AccessLogger.Info("", param...)

		return nil
	}
}
