package repo

import "gorm.io/gorm"

type FileRepository interface {
	GetDB() *gorm.DB
}

type RepoImpl struct {
	DB      *gorm.DB
	Version int
}

func NewFileRepository(db *gorm.DB) FileRepository {
	return &RepoImpl{
		DB:      db,
		Version: 1,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}
