package models

import (
	"github.com/123508/xservergo/pkg/util"
)

// UserRole 用户-角色关联表
type UserRole struct {
	UserID     util.UUID  `gorm:"column:user_id;primaryKey;comment '用户ID'"`
	RoleID     util.UUID  `gorm:"column:role_id;primaryKey;comment '角色ID'"`
	Status     int8       `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	OperatorID *util.UUID `gorm:"column:operator_id;comment '操作人(null=系统)'"`
	AuditFields
}

func (UserRole) TableName() string {
	return "user_role"
}
