package models

import (
	"time"

	"github.com/123508/xservergo/pkg/util/id"
)

// File 采用可达性分析法分析文件是否可以被回收
type File struct {
	ID         id.UUID    `gorm:"column:id;comment '文件ID'"`
	FileHash   string     `gorm:"column:file_hash;comment '文件hash值'"`
	FileSize   uint64     `gorm:"column:file_size;comment '文件大小'"`
	FileName   string     `gorm:"file_name"`
	FileCover  string     `gorm:"column:file_cover;comment '封面'"`
	Total      uint64     `gorm:"column:total;comment '总分片'"`
	CreatedAt  *time.Time `gorm:"column:created_at;comment '创建时间'"`
	UpdatedAt  *time.Time `gorm:"column:updated_at;comment '更新时间'"`
	DeletedAt  *time.Time `gorm:"column:deleted_at;comment '删除时间'"`
	FileType   string     `gorm:"column:file_type;comment '文件分类:视频-1:mp4 2:avi 3:mov 4:mkv 5:wmv 6:flv 7:f4v 8:webm 9:mts 10:m2ts 11:rmvb 12:3gp 13:rm 14:rmvb 图片-15:jpg 16:jpeg 17:png 18:gif 19:bmp 20:tif 21:tiff 22:psd 23:raw 24:svg 25:cdr 26:ai 27:eps 28:webp 29:heif 30:ico 31:apng 音频-32:mp3 33:wav 34:aiff 35:aif 36:ape 37:flac 38:m4a 39:acc 40:ogg 41:wma 42:opus 43:mid 44:mod 45:s3m 日常-46:pdf 47:doc 48:docx 49:excel 50:txt 51:pptx 代码-52:py 53:go 54:java 55:class 56:js 57:cpp 58:c 59:cc 60:cs 61:rs 62:swift 63:kt 64:js 65:ts 66:php 67:html 68:css 69:rb 70:m 71:lua 72:pl 73:pl 74:f 75:pas 76:asm 77:h 78:dart 79:erl 数据库-80:frm 81:ibd 82:myd 83:mdf 84:ndf 85:dbf 86:db 87:sqlite 88:sqlite3 89:mdb 90:accdb 压缩包-91:zip 92:rar 93:7z 94:tgz 95:tar.bz2 96:gz 97:bz2 98:z 99:jar 100:cab'"`
	Status     uint64     `gorm:"column:status;comment '标记删除: 1上传中 3分片存储 4合并存储 '"`
	StoreType  uint64     `gorm:"column:store_type;comment '1本地 2阿里云存储'"`
	DirectPath string     `gorm:"column:direct_path;comment '合并文件存储路径'"`
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
