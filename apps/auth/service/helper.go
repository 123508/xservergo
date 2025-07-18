package service

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

type AccessTokenClaims struct {
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

	claims := AccessTokenClaims{
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
func ParseJWT(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(frontendSecretKey), nil
	})

	if err != nil {
		return nil, errors.New("解析令牌失败")
	}

	if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {

		if claims.Issuer != Md5Hash("user service delivery this token") {
			return claims, errors.New("非法令牌")
		}

		return claims, nil
	} else {
		return nil, errors.New("令牌过期")
	}
}

// GenerateRefreshToken 生成安全的 refresh token
func GenerateRefreshToken() (string, error) {
	// 推荐 token 长度为 32 字节 (256 位)，提供足够的安全性
	tokenLength := 32

	// 创建字节切片存储随机数据
	tokenBytes := make([]byte, tokenLength)

	// 使用 crypto/rand 生成加密安全的随机数
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}

	// 使用 URL 安全的 Base64 编码（无填充）
	token := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(tokenBytes)
	return token, nil
}
