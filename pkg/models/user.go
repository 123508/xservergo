package models

import (
	"github.com/123508/xservergo/pkg/util"
)

// User 用户表
type User struct {
	ID       util.UUID `gorm:"column:id;comment '用户ID'"`
	NickName string    `gorm:"column:nickname;comment '用户昵称'"`
	UserName string    `gorm:"column:username;comment '用户账号'"`
	Email    string    `gorm:"column:email;comment '用户邮箱'"`
	Phone    string    `gorm:"column:phone;comment '用户手机号'"`
	Gender   uint32    `gorm:"column:gender;comment '用户性别 1男 0女'"`
	Avatar   string    `gorm:"column:avatar; comment '用户头像'"`
	Status   uint32    `gorm:"column:status;comment '用户状态 0正常 1冻结'"`
	AuditFields
}
