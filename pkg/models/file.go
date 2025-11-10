package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type File struct {
	ID        id.UUID    `gorm:"column:id;comment '文件ID'"`
	FileHash  string     `gorm:"column:file_hash;comment '文件hash值'"`
	ParentID  id.UUID    `gorm:"column:parent_id;comment '父节点ID'"`
	FileSize  uint64     `gorm:"column:file_size;comment '文件大小'"`
	FileName  string     `gorm:"column:file_name;comment '文件名称(包含路径)'"`
	FileCover string     `gorm:"column:file_cover;comment '封面'"`
	Count     uint64     `gorm:"colum:count;comment '引用计数'"`
	Total     uint64     `gorm:"column:total;comment '总分片'"`
	CreatedAt *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt *time.Time `gorm:"column:updated_at;comment '更新时间'"`
	DeletedAt *time.Time `gorm:"column:deleted_at;comment '进入回收站时间'"`
	FileType  uint64     `gorm:"column:file_type;comment '文件分类:1视频 2音频 3图片 4pdf 5doc 6excel 7txt 8code 9zip 10其他'"`
	IsPublic  bool       `gorm:"column:is_public;comment '0不公开 1公开'"`
	Status    uint64     `gorm:"column:status;comment '标记删除: 0删除 1回收站 2正常 3转码中 4转码失败 5上传中 6上传失败 7合并存储 8分片存储'"`
	StoreType uint64     `gorm:"column:store_type;comment '1本地 2阿里云存储'"`
}

func (File) TableName() string {
	return "file"
}

func (f File) GetID() id.UUID {
	return f.ID
}

func (f File) GetCreatedTime() time.Time {
	return *f.CreatedAt
}
