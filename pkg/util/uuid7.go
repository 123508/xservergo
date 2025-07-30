package util

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// UUID 表示符合 UUID v7 规范的 128 位标识符
type UUID [16]byte

// NewUUID 生成一个新的 UUID v7
func NewUUID() UUID {
	var u UUID
	now := time.Now().UnixMilli()

	// 48 位时间戳 (前 6 字节)
	binary.BigEndian.PutUint64(u[0:8], uint64(now)<<16)

	// 生成 10 字节安全随机数
	randBytes := make([]byte, 10)
	_, _ = rand.Read(randBytes) // 忽略错误，因为 crypto/rand 在 Linux 上总是返回 nil

	// 填充随机部分 (第 6-16 字节)
	copy(u[6:], randBytes)

	// 设置版本位 (0111) - 第 6 字节的高4位
	u[6] = (u[6] & 0x0F) | 0x70 // 设置版本为 7 (0111)

	// 设置变体位 (10) - 第 8 字节的高2位
	u[8] = (u[8] & 0x3F) | 0x80 // 设置变体位为 10 (RFC 4122)

	return u
}

// String 返回标准 UUID 字符串格式 (8-4-4-4-12)
func (u UUID) String() string {
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf)
}

// Value 实现 driver.Valuer 接口，用于安全插入数据库
func (u UUID) Value() (driver.Value, error) {
	return u[:], nil
}

// Scan 实现 sql.Scanner 接口，用于从数据库安全读取
func (u *UUID) Scan(src interface{}) error {
	switch src := src.(type) {
	case []byte:
		if len(src) != 16 {
			return fmt.Errorf("uuid7: invalid UUID length: %d", len(src))
		}
		copy(u[:], src)
		return nil
	case string:
		// 处理字符串格式的 UUID
		if len(src) != 36 {
			return fmt.Errorf("uuid7: invalid UUID string length: %d", len(src))
		}
		return u.unmarshalString(src)
	case nil:
		return errors.New("uuid7: cannot scan nil into UUID")
	default:
		return fmt.Errorf("uuid7: cannot scan type %T into UUID", src)
	}
}

// unmarshalString 从字符串解析 UUID
func (u *UUID) unmarshalString(s string) error {
	if len(s) != 36 {
		return fmt.Errorf("uuid7: invalid UUID string length: %d", len(s))
	}

	// 验证格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return errors.New("uuid7: invalid UUID format")
	}

	// 解析各部分
	_, err := hex.Decode(u[0:4], []byte(s[0:8]))
	if err != nil {
		return err
	}
	_, err = hex.Decode(u[4:6], []byte(s[9:13]))
	if err != nil {
		return err
	}
	_, err = hex.Decode(u[6:8], []byte(s[14:18]))
	if err != nil {
		return err
	}
	_, err = hex.Decode(u[8:10], []byte(s[19:23]))
	if err != nil {
		return err
	}
	_, err = hex.Decode(u[10:16], []byte(s[24:36]))
	return err
}

// IsZero 检查 UUID 是否为零值
func (u UUID) IsZero() bool {
	for _, b := range u {
		if b != 0 {
			return false
		}
	}
	return true
}

// Time 返回 UUID 中的时间戳部分
func (u UUID) Time() time.Time {
	// 提取前 48 位时间戳
	ms := binary.BigEndian.Uint64(u[0:8]) >> 16
	return time.UnixMilli(int64(ms))
}

// FromString 从字符串创建 UUID
func FromString(s string) (UUID, error) {
	var u UUID
	err := u.unmarshalString(s)
	return u, err
}

// Must 创建 UUID，如果出错则 panic
func Must(u UUID, err error) UUID {
	if err != nil {
		panic(err)
	}
	return u
}

// NullUUID 表示可为 NULL 的 UUID
type NullUUID struct {
	UUID  UUID
	Valid bool
}

// Scan 实现 sql.Scanner 接口
func (nu *NullUUID) Scan(value interface{}) error {
	if value == nil {
		nu.UUID, nu.Valid = UUID{}, false
		return nil
	}

	err := nu.UUID.Scan(value)
	if err != nil {
		return err
	}

	nu.Valid = true
	return nil
}

// Value 实现 driver.Valuer 接口
func (nu NullUUID) Value() (driver.Value, error) {
	if !nu.Valid {
		return nil, nil
	}
	return nu.UUID.Value()
}

// Marshal 实现 proto.Marshaler 接口
func (u UUID) Marshal() ([]byte, error) {
	return u[:], nil // 直接返回底层数组的切片
}

// Unmarshal 实现 proto.Unmarshaler 接口
func (u *UUID) Unmarshal(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("invalid UUID length: expected 16 bytes, got %d", len(data))
	}
	copy(u[:], data)
	return nil
}

// MarshalBinary 实现 encoding.BinaryMarshaler 接口
func (u UUID) MarshalBinary() ([]byte, error) {
	return u[:], nil
}

// UnmarshalBinary 实现 encoding.BinaryUnmarshaler 接口
func (u *UUID) UnmarshalBinary(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("invalid UUID length: expected 16 bytes, got %d", len(data))
	}
	copy(u[:], data)
	return nil
}

// MarshalText 实现 encoding.TextMarshaler 接口 (用于JSON等文本序列化)
func (u UUID) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText 实现 encoding.TextUnmarshaler 接口
func (u *UUID) UnmarshalText(text []byte) error {
	return u.unmarshalString(string(text))
}

// 系统级固定UUID (v7格式)
var SystemUUID = UUID{
	0x00, 0x00, 0x00, 0x00, // 时间戳高位 (全零)
	0x00, 0x00, // 时间戳低位 (全零)
	0x70, 0x00, // 版本7(0111) + 随机位
	0x80, 0x00, // 变体位(10) + 随机位
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 固定后缀
}
