package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util"
)

type AuditFields struct {
	CreatedAt time.Time  `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt time.Time  `gorm:"column:updated_at;comment '更新时间'"`
	DeletedAt *time.Time `gorm:"column:deleted_at;comment '删除时间(软删除)'"`
	IsDeleted int8       `gorm:"column:is_deleted;->;comment '是否被删除'"`
	Version   int        `gorm:"column:version;comment '版本号'"`
	CreatedBy *util.UUID `gorm:"column:created_by;comment '创建人ID'"`
	UpdatedBy *util.UUID `gorm:"column:updated_by;comment '修改人ID'"`
}
