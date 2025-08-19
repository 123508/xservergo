package models

import "github.com/123508/xservergo/pkg/util"

// Policy represents a policy in the system.
type Policy struct {
	ID          util.UUID `gorm:"column:id;comment '策略id'"`
	Code        string    `gorm:"column:code;comment '策略唯一标识符'"`
	Name        string    `gorm:"column:name;comment '策略名称'"`
	Description string    `gorm:"column:description;comment '策略详细描述'"`
	Status      int8      `gorm:"column:status;comment '策略是否启用:0不启用 1启用'"`
	AuditFields
}

// TableName returns the table name of the Policy model.
func (Policy) TableName() string {
	return "policy"
}
