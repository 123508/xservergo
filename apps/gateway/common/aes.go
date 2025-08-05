package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/123508/xservergo/pkg/config"
)

var Key, _ = base64.StdEncoding.DecodeString(config.Conf.AESConfig.Key)

var IV, _ = base64.StdEncoding.DecodeString(config.Conf.AESConfig.IV)

// EncryptAES AES-256-CBC加密
func EncryptAES(plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}
	// PKCS#7填充
	Plaintext := pkcs7Pad(plaintext, aes.BlockSize)

	// 加密
	ciphertext = make([]byte, len(Plaintext))
	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext, Plaintext)

	return ciphertext, nil
}

// DecryptAES AES解密
func DecryptAES(ciphertext []byte) (plaintext []byte, err error) {

	block, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, IV)
	Plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(Plaintext, ciphertext)

	// 去除PKCS#7填充
	return pkcs7Unpad(Plaintext), nil
}

// PKCS#7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS#7去除填充
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
