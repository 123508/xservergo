package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type FileChunk struct {
	ID        id.UUID    `gorm:"column:id;comment '分片id'"`
	ChunkHash string     `gorm:"column:chunk_hash;comment '分片内容hash'"`
	ChunkName string     `gorm:"column:chunk_name;comment '分片路径'"`
	CreatedAt *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt *time.Time `gorm:"column:updated_at;comment '更新时间'"`
}

func (f FileChunk) TableName() string {
	return "file_chunk"
}

func (f FileChunk) GetID() id.UUID {
	return f.ID
}

func (f FileChunk) GetCreatedTime() time.Time {
	return *f.CreatedAt
}
