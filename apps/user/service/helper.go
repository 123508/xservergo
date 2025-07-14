package service

import (
	"crypto/sha256"
	"encoding/hex"
)

// Encryption sha256加密算法
func Encryption(origin string) string {
	hash := sha256.New()
	hash.Write([]byte(origin))
	hashBytes := hash.Sum(nil)
	res := hex.EncodeToString(hashBytes)
	return res
}
