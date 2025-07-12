package models

import "github.com/123508/xservergo/pkg/util"

type Role struct {
	ID          util.UUID `gorm:"column:id;comment '角色表'"`
	Code        string    `gorm:"column:code;comment '角色唯一标识符'"`
	Name        string    `gorm:"column:name;comment '角色名称'"`
	Description string    `gorm:"column:description;comment '角色详细描述'"`
	Status      int8      `gorm:"column:status;comment '角色是否启用:0不启用 1启用'"`
	AuditFields
}
