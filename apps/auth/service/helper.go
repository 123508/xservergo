package service

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"github.com/123508/xservergo/pkg/config"
	"github.com/123508/xservergo/pkg/util"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"time"
)

// Md5Hash 用做查询条件的处理
func Md5Hash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

type FrontendClaims struct {
	UserId util.UUID `json:"user_id"`
	Perms  []string  `json:"perms"`
	PVer   uint64    `json:"p_ver"`
	jwt.RegisteredClaims
}

var frontendSecretKey = config.Conf.Jwt.AdminSecretKey

// GenerateJWT 产生一个jwt令牌
func GenerateJWT(
	userId util.UUID,
	perms []string,
	version uint64,
) (string, error) {

	jti, _ := uuid.NewV7()

	claims := FrontendClaims{
		UserId: userId,
		Perms:  perms,
		PVer:   version,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(config.Conf.AdminTtl) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    Md5Hash("user service delivery this token"),
			ID:        jti.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(frontendSecretKey))
	if err != nil {
		return "", errors.New("签发token失败")
	}

	return signedToken, nil
}

// ParseJWT 解析jwt令牌
func ParseJWT(tokenString string) (*FrontendClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &FrontendClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(frontendSecretKey), nil
	})

	if err != nil {
		return nil, errors.New("解析令牌失败")
	}

	if claims, ok := token.Claims.(*FrontendClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("令牌过期")
	}
}
