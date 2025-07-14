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
	// 基础字段
	"id":          true,
	"name":        true,
	"code":        true,
	"description": true,
	"status":      true,

	// 用户相关字段
	"user_id":  true,
	"username": true,
	"nickname": true,
	"email":    true,
	"phone":    true,
	"gender":   true,
	"avatar":   true,
	"password": true,

	// 权限和角色字段
	"role_id":       true,
	"group_id":      true,
	"permission_id": true,
	"parent_id":     true,
	"type":          true,
	"resource":      true,
	"method":        true,
	"path":          true,
	"operator_id":   true,

	// 登录相关字段
	"login_type":   true,
	"login_status": true,
	"fail_reason":  true,
	"login_ip":     true,
	"user_agent":   true,
	"device":       true,

	// 时间戳字段
	"created_at":       true,
	"updated_at":       true,
	"deleted_at":       true,
	"is_deleted":       true,
	"deleted_date":     true,
	"deleted_at_fixed": true,

	// 审计字段
	"version":         true,
	"created_by":      true,
	"updated_by":      true,
	"last_updated_by": true,
}

func IsValidField(field string) bool {
	// 禁止特殊字符
	if strings.ContainsAny(field, ";'\"-/*() ") {
		return false
	}
	return allowedFields[field]
}
