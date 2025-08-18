package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// UserRole 用户-角色关联表
type UserRole struct {
	UserID     id.UUID  `gorm:"column:user_id;primaryKey;comment '用户ID'"`
	RoleID     id.UUID  `gorm:"column:role_id;primaryKey;comment '角色ID'"`
	Status     int8     `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	OperatorID *id.UUID `gorm:"column:operator_id;comment '操作人(null=系统)'"`
	AuditFields
}

func (UserRole) TableName() string {
	return "user_role"
}
