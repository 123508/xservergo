package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// RolePermission 角色-权限关联表
type RolePermission struct {
	RoleID       id.UUID  `gorm:"column:role_id;primaryKey;comment '角色ID'"`
	PermissionID id.UUID  `gorm:"column:permission_id;primaryKey;comment '权限ID'"`
	Status       int8     `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	OperatorID   *id.UUID `gorm:"column:operator_id;comment '操作人(null=系统)'"`
	AuditFields
}

func (RolePermission) TableName() string {
	return "role_permission"
}
