package models

import (
	"github.com/123508/xservergo/pkg/util"
	"time"
)

type UserLogin struct {
	UserID    util.UUID `gorm:"column:user_id;comment '用户ID'"`
	Password  string    `gorm:"column:password; comment '加密后的密码'"`
	CreatedAt time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt time.Time `gorm:"column:updated_at;comment '更新时间'"`
	DeletedAt time.Time `gorm:"column:deleted_at;comment '删除时间'"`
	IsDeleted int       `gorm:"column:is_deleted;comment '是否被删除'"`
	Version   int       `gorm:"column:version;comment '版本号'"`
}
