package models

import (
	"github.com/123508/xservergo/pkg/util"
)

type UserLogin struct {
	UserID   util.UUID `gorm:"column:user_id;comment '用户ID'"`
	Password string    `gorm:"column:password; comment '加密后的密码'"`
	AuditFields
}
