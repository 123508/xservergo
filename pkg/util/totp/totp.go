package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

type TOTP struct {
	Secret   string // Base32编码的密钥
	Interval int    // 时间间隔，单位为秒
	Issuer   string // 发行者名称
	Username string // 用户名
}

func (t *TOTP) checkAndRepair() error {
	if t.Interval <= 0 {
		t.Interval = 30 // 默认30秒
	}

	if t.Secret == "" { // 如果没有提供密钥，则生成一个随机密钥
		secret, err := generateRandomBase32Secret()
		if err != nil {
			return err
		}
		t.Secret = secret
	}
	t.Secret = strings.ToUpper(t.Secret)

	if t.Issuer == "" {
		t.Issuer = "XServerGo" // 默认发行者
	}

	if t.Username == "" {
		t.Username = "DefaultUser" // 默认用户名
	}
	return nil
}

// GetTOTPToken 获取 TOTP 验证码
func (t *TOTP) GetTOTPToken() (string, error) {
	if err := t.checkAndRepair(); err != nil {
		return "", err
	}

	// 解码Base32密钥
	key, err := base32.StdEncoding.DecodeString(t.Secret)
	if err != nil {
		return "", fmt.Errorf("无效的 Base32 密钥: %w", err)
	}

	// 计算时间步
	timestep := time.Now().Unix() / int64(t.Interval)

	// 将时间步转换为8字节的大端序字节数组
	timestepBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestepBytes, uint64(timestep))

	// 计算HMAC-SHA1
	mac := hmac.New(sha1.New, key)
	mac.Write(timestepBytes)
	hash := mac.Sum(nil)

	// 动态截断
	offset := hash[len(hash)-1] & 0x0F
	truncatedHash := hash[offset : offset+4]

	// 计算验证码
	code := binary.BigEndian.Uint32(truncatedHash) & 0x7FFFFFFF

	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyToken 验证提供的TOTP验证码是否正确
func (t *TOTP) VerifyToken(token string) (bool, error) {
	// 获取当前的TOTP验证码
	currentToken, err := t.GetTOTPToken()
	if err != nil {
		return false, err
	}

	// 比较提供的token和当前生成的token
	return token == currentToken, nil
}

// GenerateQRCodeURL 生成用于二维码的URL
func (t *TOTP) GenerateQRCodeURL() (string, error) {
	err := t.checkAndRepair()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d",
		t.Issuer, t.Username, t.Secret, t.Issuer, t.Interval), nil
}

// generateRandomBase32Secret 生成一个长度为16的随机Base32密钥
func generateRandomBase32Secret() (string, error) {
	const secretLength = 16
	const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// 使用crypto/rand生成安全的随机字节
	randomBytes := make([]byte, secretLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("无法生成TOTP密钥: %w", err)
	}

	// 将随机字节转换为Base32字符
	b := make([]byte, secretLength)
	for i := range b {
		b[i] = base32Chars[randomBytes[i]%32]
	}
	return string(b), nil
}
