package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type FileUser struct {
	ID        id.UUID    `gorm:"column:id;comment '唯一标识ID'"`
	FileId    id.UUID    `gorm:"column:file_id;comment '文件id'"`
	UserId    id.UUID    `gorm:"column:user_id;comment '用户id'"`
	FileAlias string     `gorm:"column:file_alias; comment '文件别名'"`
	CreatedAt *time.Time `gorm:"column:created_at;comment '创建时间'"`
	DeletedAt *time.Time `gorm:"column:deleted_at;comment '进入回收站时间'"`
}

func (FileUser) TableName() string {
	return "file_user"
}

func (f FileUser) GetID() id.UUID {
	return f.ID
}

func (f FileUser) GetCreatedTime() time.Time {
	return *f.CreatedAt
}
