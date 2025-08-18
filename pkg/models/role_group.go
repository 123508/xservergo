package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// RoleGroup 角色-用户组关联表
type RoleGroup struct {
	RoleID     id.UUID  `gorm:"column:role_id;primaryKey;comment '角色ID'"`
	GroupID    id.UUID  `gorm:"column:group_id;primaryKey;comment '用户组ID'"`
	Status     int8     `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	OperatorID *id.UUID `gorm:"column:operator_id;comment '操作人(null=系统)'"`
	AuditFields
}

func (RoleGroup) TableName() string {
	return "role_group"
}
