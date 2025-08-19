package models

// PermissionPolicyRelation represents the relationship between a permission and a policy.
type PermissionPolicyRelation struct {
	PermissionCode string `gorm:"column:permission_code;comment '权限唯一标识符'"`
	PolicyCode     string `gorm:"column:policy_code;comment '策略唯一标识符'"`
	Status         int8   `gorm:"column:status;comment '启用状态: 0禁用 1启用'"`
	AuditFields
}

// TableName returns the table name of the PermissionPolicyRelation model.
func (PermissionPolicyRelation) TableName() string {
	return "permission_policy_relation"
}
