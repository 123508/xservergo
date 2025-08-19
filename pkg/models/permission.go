package models

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// PermissionType 权限类型枚举
type PermissionType string

const (
	PermissionTypeAPI    PermissionType = "API"
	PermissionTypeMenu   PermissionType = "MENU"
	PermissionTypeButton PermissionType = "BUTTON"
	PermissionTypeData   PermissionType = "DATA"
	PermissionTypeField  PermissionType = "FIELD"
	PermissionTypeModule PermissionType = "MODULE"
	PermissionTypeFile   PermissionType = "FILE"
	PermissionTypeTask   PermissionType = "TASK"
)

type Permission struct {
	ID          id.UUID        `gorm:"column:id;comment '权限ID'"`
	Code        string         `gorm:"column:code;comment '权限唯一标识符'"`
	Name        string         `gorm:"column:name;comment '权限名称'"`
	Description string         `gorm:"column:description;comment '权限详细描述'"`
	ParentID    *id.UUID       `gorm:"column:parent_id;comment '父级ID,没有就置空'"`
	Type        PermissionType `gorm:"column:type;comment '权限类型'"`
	Resource    string         `gorm:"column:resource;comment '权限对应资源'"`
	Method      string         `gorm:"column:method;comment '权限对应方法类型'"`
	Status      int8           `gorm:"column:status;comment '权限是否启用:0不启用 1启用'"`
	NeedPolicy  bool           `gorm:"column:need_policy;comment '是否需要策略'"`
	AuditFields
}

func (Permission) TableName() string {
	return "permission"
}
