package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type FileAlias struct {
	ID          id.UUID    `gorm:"column:id;comment '标识id'"`
	FileID      id.UUID    `gorm:"column:file_id;comment '文件id'"`
	UserID      id.UUID    `gorm:"column:user_id;comment '用户id'"`
	ParentID    id.UUID    `gorm:"column:parent_id;comment '父节点id'"`
	FileName    string     `gorm:"file_name;comment '文件名称'"`
	CreatedAt   *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt   *time.Time `gorm:"column:updated_at;comment '更新时间'"`
	IsDirectory bool       `gorm:"column:is_directory;comment '0:文件 1:目录'"`
	IsPublic    bool       `gorm:"column:is_public;comment '0不公开 1公开'"`
}

func (f *FileAlias) TableName() string {
	return "file_alias"
}
