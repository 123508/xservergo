package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/util"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"net/http"
	"time"
)

type QueryType uint64

const (
	PHONE    QueryType = 0
	EMAIL    QueryType = 1
	USERNAME QueryType = 2
)

// Encryption sha256加密算法
func Encryption(origin string) string {
	hash := sha256.New()
	hash.Write([]byte(origin))
	hashBytes := hash.Sum(nil)
	res := hex.EncodeToString(hashBytes)
	return res
}

func ParseRepoErrorToCommonError(err error, defaultText string) error {
	switch err.(type) {
	case *cerrors.SQLError:
		sqlErr := err.(*cerrors.SQLError)
		return cerrors.NewCommonError(sqlErr.Code, sqlErr.Message, "", sqlErr)
	case *cerrors.ParamError:
		paramErr := err.(*cerrors.ParamError)
		return cerrors.NewCommonError(paramErr.Code, paramErr.Message, "", paramErr)
	default:
		return cerrors.NewCommonError(http.StatusInternalServerError, defaultText, "", err)
	}
}

func (s *ServiceImpl) GenerateRequestId(ctx context.Context, expire time.Duration) (string, error) {
	requestId := uuid.New().String()
	if err := s.Rds.Set(ctx, util.TakeKey("userservice", "user", "requestId", requestId), "ok", expire).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "生产requestId失败", "", err)
	}
	return requestId, nil
}

func (s *ServiceImpl) VerityRequestID(ctx context.Context, requestId string) error {
	//校验requestId
	result, err := s.Rds.Get(ctx, util.TakeKey("userservice", "user", "requestId", requestId)).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	} else if result != "ok" || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}
	return nil
}
