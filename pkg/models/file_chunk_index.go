package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

type FileChunkIndex struct {
	FileID     id.UUID    `gorm:"column:file_id;comment '文件id'"`
	ChunkID    id.UUID    `gorm:"column:chunk_id;comment '分片id'"`
	ChunkIndex uint64     `gorm:"column:chunk_index;comment '分片序号'"`
	CreatedAt  *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt  *time.Time `gorm:"column:updated_at;comment '更新时间'"`
}

func (FileChunkIndex) TableName() string {
	return "file_chunk_index"
}
