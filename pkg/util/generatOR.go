package util

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/123508/xservergo/pkg/component/serializer"
	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
	"image/color"
	"time"
)

type QRLoginSession struct {
	UUID       string    // 唯一标识
	CreatedAt  time.Time // 创建时间
	ClientIP   string    // 请求IP (IPv4/IPv6)
	BrowserSig string    // 浏览器指纹哈希
	ExpiresAt  time.Time // 过期时间
}

func NewQRLoginSession(clientIp, browserSig string, ttl time.Duration) *QRLoginSession {
	return &QRLoginSession{
		UUID:       "QRLogin-" + uuid.New().String(),
		CreatedAt:  time.Now(),
		ClientIP:   clientIp,
		BrowserSig: browserSig,
		ExpiresAt:  time.Now().Add(ttl),
	}
}

func (q *QRLoginSession) checkAndRepair() {
	if q.UUID == "" {
		q.UUID = "QRLogin-" + uuid.New().String()
	}

	if q.CreatedAt.IsZero() {
		q.CreatedAt = time.Now()
	}

	if q.ExpiresAt.IsZero() {
		q.ExpiresAt = time.Now().Add(10 * time.Minute)
	}

	if q.ClientIP == "" {
		q.ClientIP = "0.0.0.0"
	}

	if q.BrowserSig == "" {
		q.BrowserSig = "edge"
	}
}

func (q *QRLoginSession) Serialize() (string, error) {
	q.checkAndRepair()
	wrapper := serializer.NewSerializerWrapper(serializer.JSON)
	serialize, err := wrapper.Serialize(q)
	return string(serialize), err
}

func (q *QRLoginSession) GenerateQR(
	size int, //二维码尺寸
	Ecc string, //纠错级别 L M Q H
) ([]byte, string, error) {
	q.checkAndRepair()
	content, err := q.Serialize()

	if err != nil {
		return nil, "", err
	}

	return GenerateQR(content, size, "#FFFFFF", "#000000", Ecc)
}

func (q *QRLoginSession) DeSerialize(data string) error {
	wrapper := serializer.NewSerializerWrapper(serializer.JSON)
	return wrapper.Deserialize([]byte(data), q)
}

// 颜色转换：十六进制字符串 -> RGBA
func parseHexColor(hex string) (color.RGBA, error) {
	c := color.RGBA{A: 0xff}

	if len(hex) == 3 {
		_, err := fmt.Sscanf(hex, "%01x%01x%01x", &c.R, &c.G, &c.B)
		c.R *= 17
		c.G *= 17
		c.B *= 17
		return c, err
	}

	if len(hex) == 4 {
		_, err := fmt.Sscanf(hex, "#%01x%01x%01x", &c.R, &c.G, &c.B)
		c.R *= 17
		c.G *= 17
		c.B *= 17
		return c, err
	}

	if len(hex) == 6 {
		_, err := fmt.Sscanf(hex, "%02x%02x%02x", &c.R, &c.G, &c.B)
		return c, err
	}

	if len(hex) == 7 {
		_, err := fmt.Sscanf(hex, "#%02x%02x%02x", &c.R, &c.G, &c.B)
		return c, err
	}

	return c, errors.New("不正确的十六进制字符串")
}

// 获取容错级别
func getECCLevel(level string) qrcode.RecoveryLevel {
	switch level {
	case "L":
		return qrcode.Low
	case "Q":
		return qrcode.High
	case "H":
		return qrcode.Highest
	default:
		return qrcode.Medium // 默认中等容错
	}
}

// GenerateQR 生成二维码图片（返回PNG二进制和Base64）
func GenerateQR(content string, size int, fgHex, bgHex, ecc string) ([]byte, string, error) {
	// 1. 解析颜色
	fgColor, err := parseHexColor(fgHex)
	if err != nil {
		return nil, "", err
	}
	bgColor, err := parseHexColor(bgHex)
	if err != nil {
		return nil, "", err
	}

	// 2. 创建二维码
	qr, err := qrcode.New(content, getECCLevel(ecc))
	if err != nil {
		return nil, "", err
	}

	// 3. 设置颜色
	qr.ForegroundColor = fgColor
	qr.BackgroundColor = bgColor

	// 4. 生成PNG
	pngData, err := qr.PNG(size)
	if err != nil {
		return nil, "", err
	}

	// 5. 返回结果
	base64Str := base64.StdEncoding.EncodeToString(pngData)
	return pngData, base64Str, nil
}
