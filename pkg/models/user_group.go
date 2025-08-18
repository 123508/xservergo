package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// UserGroup 用户组表
type UserGroup struct {
	ID       id.UUID  `gorm:"column:id;comment '用户组ID'"`
	Name     string   `gorm:"column:name;comment '用户组名称'"`
	Code     string   `gorm:"column:code;comment '用户组唯一标识符'"`
	Status   int8     `gorm:"column:status;comment '权限是否启用:0不启用 1启用'"`
	ParentID *id.UUID `gorm:"column:parent_id;comment '父级ID,没有就置空'"`
	Path     string   `gorm:"column:path;->;comment '用户组路径'"`
	AuditFields
}

func (UserGroup) TableName() string {
	return "user_group"
}
