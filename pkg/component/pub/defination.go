package pub

import (
	"strings"
	"time"
)

//对表的主键的类型约束

type IntegerNumber interface {
	~int | ~uint | ~int64 | ~uint64 | ~int32 | ~uint32 | ~int16 | ~uint16 | ~int8 | ~uint8
}

//对表的类型约束

type ItemType[E IntegerNumber] interface {
	GetID() E
	GetCreatedTime() time.Time
}

// 只允许特定字段名
var allowedFields = map[string]bool{
	"id":         true,
	"name":       true,
	"created_at": true,
	"updated_at": true,
	"deleted_at": true,
	"user_id":    true,
}

func IsValidField(field string) bool {
	// 禁止特殊字符
	if strings.ContainsAny(field, ";'\"-/*() ") {
		return false
	}
	return allowedFields[field]
}
