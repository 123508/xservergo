package urds

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func VerityRequestID(rds *redis.Client, keys Keys, ctx context.Context, requestId string, duration time.Duration) error {

	token := keys.RequestIdKey(requestId)

	//校验requestId
	result, err := rds.Get(ctx, token).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	} else if result != "ok" || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}
	//刷新过期时间
	rds.Expire(ctx, token, duration)
	return nil
}

func GenerateRequestId(rds *redis.Client, keys Keys, ctx context.Context, expire time.Duration) (string, error) {
	requestId := uuid.New().String()
	if err := rds.Set(ctx, keys.RequestIdKey(requestId), "ok", expire).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "生产requestId失败", "", err)
	}
	return requestId, nil
}

func GenerateUploadId(rds *redis.Client, keys *FileKeys, ctx context.Context, expire time.Duration) (string, error) {
	uploadId := uuid.New().String()
	if err := rds.Set(ctx, keys.UploadIdKey(uploadId), "ok", expire).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "生产requestId失败", "", err)
	}
	return uploadId, nil
}
