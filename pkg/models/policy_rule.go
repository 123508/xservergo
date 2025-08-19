package models

import "github.com/123508/xservergo/pkg/util"

// AttributeType defines the type of attribute in a policy rule.
type AttributeType string

const (
	AttributeTypeString  AttributeType = "String"
	AttributeTypeInt     AttributeType = "Int"
	AttributeTypeInt8    AttributeType = "Int8"
	AttributeTypeInt16   AttributeType = "Int16"
	AttributeTypeInt32   AttributeType = "Int32"
	AttributeTypeInt64   AttributeType = "Int64"
	AttributeTypeUint    AttributeType = "Uint"
	AttributeTypeUint8   AttributeType = "Uint8"
	AttributeTypeUint16  AttributeType = "Uint16"
	AttributeTypeUint32  AttributeType = "Uint32"
	AttributeTypeUint64  AttributeType = "Uint64"
	AttributeTypeFloat32 AttributeType = "Float32"
	AttributeTypeFloat64 AttributeType = "Float64"
	AttributeTypeBoolean AttributeType = "Boolean"
	AttributeTypeDate    AttributeType = "Date"
	AttributeTypeList    AttributeType = "List"
)

// Operator defines the comparison operator in a policy rule.
type Operator string

const (
	OperatorEqual        Operator = "="
	OperatorNotEqual     Operator = "!="
	OperatorGreaterThan  Operator = ">"
	OperatorLessThan     Operator = "<"
	OperatorGreaterEqual Operator = ">="
	OperatorLessEqual    Operator = "<="
	OperatorContains     Operator = "Contains"
	OperatorStartsWith   Operator = "StartsWith"
	OperatorEndsWith     Operator = "EndsWith"
	OperatorRegex        Operator = "Regex"
	OperatorIn           Operator = "In"
)

// PolicyRule represents a rule within a policy.
type PolicyRule struct {
	ID             util.UUID     `gorm:"column:id;comment '策略规则id'"`
	PolicyCode     string        `gorm:"column:policy_code;comment '策略唯一标识符'"`
	AttributeType  AttributeType `gorm:"column:attribute_type;comment '属性类型'"`
	AttributeKey   string        `gorm:"column:attribute_key;comment '属性键'"`
	AttributeValue string        `gorm:"column:attribute_value;comment '属性值'"`
	Operator       Operator      `gorm:"column:operator;comment '操作符'"`
	Status         int8          `gorm:"column:status;comment '规则是否启用:0不启用 1启用'"`
	AuditFields
}

// TableName returns the table name of the PolicyRule model.
func (PolicyRule) TableName() string {
	return "policy_rule"
}
