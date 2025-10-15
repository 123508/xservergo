package urds

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func VerityRequestID(rds *redis.Client, keys Keys, ctx context.Context, requestId string) error {

	token := keys.RequestIdKey(requestId)

	//校验requestId
	result, err := rds.Get(ctx, token).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		logs.ErrorLogger.Error("redis查询requestId错误", zap.String("requestId", requestId), zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	} else if result != "ok" || errors.Is(err, redis.Nil) {
		logs.ErrorLogger.Error("requestId过期", zap.String("requestId", requestId))
		return cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}
	//刷新过期时间
	rds.Expire(ctx, token, 20*time.Minute)
	return nil
}

func GenerateRequestId(rds *redis.Client, keys Keys, ctx context.Context, expire time.Duration) (string, error) {
	requestId := uuid.New().String()
	if err := rds.Set(ctx, keys.RequestIdKey(requestId), "ok", expire).Err(); err != nil {
		logs.ErrorLogger.Error("生产requestId失败", zap.String("requestId", requestId), zap.Error(err))
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "生产requestId失败", "", err)
	}
	return requestId, nil
}
