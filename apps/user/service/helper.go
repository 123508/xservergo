package service

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/123508/xservergo/pkg/cerrors"
	"net/http"
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
