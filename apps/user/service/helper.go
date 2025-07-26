package service

import (
	"crypto/sha256"
	"encoding/hex"
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
