package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type FileChunk struct {
	ID          id.UUID    `gorm:"column:id;comment '分片id,用来做缓存键处理'"`
	FileID      id.UUID    `gorm:"column:file_id;comment '关联文件ID'"`
	ChunkNumber uint64     `gorm:"column:chunk_number;comment '分片序号'"`
	ChunkSize   uint64     `gorm:"column:chunk_size;comment '每片文件大小'"`
	ChunkPath   string     `gorm:"column:chunk_path;comment '分片路径'"`
	CreatedAt   *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt   *time.Time `gorm:"column:updated_at;comment '更新时间'"`
}

func (f FileChunk) GetID() id.UUID {
	return f.ID
}

func (f FileChunk) GetCreatedTime() time.Time {
	return *f.CreatedAt
}
