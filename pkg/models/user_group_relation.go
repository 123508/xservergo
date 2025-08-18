package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// UserGroupRelation 用户-用户组关联表
type UserGroupRelation struct {
	UserID     id.UUID  `gorm:"column:user_id;primaryKey;comment '用户ID'"`
	GroupID    id.UUID  `gorm:"column:group_id;primaryKey;comment '用户组ID'"`
	Status     int8     `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	OperatorID *id.UUID `gorm:"column:operator_id;comment '操作人(null=系统)'"`
	AuditFields
}

func (UserGroupRelation) TableName() string {
	return "user_group_relation"
}
