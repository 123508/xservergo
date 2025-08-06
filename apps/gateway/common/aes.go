package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/123508/xservergo/pkg/config"
)

// 确保在config中已定义AESConfig.Key和AESConfig.IV（Base64编码字符串）
var Key, _ = base64.StdEncoding.DecodeString(config.Conf.AESConfig.Key)
var IV, _ = base64.StdEncoding.DecodeString(config.Conf.AESConfig.IV)

// EncryptAES AES-256-CBC加密 []byte -> Base64字符串
func EncryptAES(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(Key)
	if err != nil {
		return "", err
	}

	// PKCS#7填充
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// 加密
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext, plaintext)

	// 返回Base64编码的字符串
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES AES解密 Base64字符串 -> []byte
func DecryptAES(encrypted string) ([]byte, error) {
	// 解码Base64字符串
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, IV)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除PKCS#7填充
	return pkcs7Unpad(plaintext), nil
}

// PKCS#7填充函数 (保持不变)
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS#7去填充函数 (保持不变)
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	if padding < 1 || padding > aes.BlockSize {
		return data
	}
	return data[:length-padding]
}
