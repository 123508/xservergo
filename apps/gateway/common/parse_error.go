package common

import (
	"github.com/123508/xservergo/pkg/cerrors"
	"net/http"
)

func ParseGRPCError(err error) (int, interface{}) {

	//错误识别成功
	if gRPC, ok := cerrors.ParseToGRPCError(err).(*cerrors.GRPCError); ok {
		return int(gRPC.Code), map[string]interface{}{
			"code":    int(gRPC.Code),
			"message": gRPC.Message,
		}
	}

	//错误识别失败
	return http.StatusInternalServerError, map[string]interface{}{
		"code":    http.StatusInternalServerError,
		"message": err.Error(),
	}
}
