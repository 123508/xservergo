package repo

import "gorm.io/gorm"

type UserRepository interface {
	GetDB() *gorm.DB
}

type RepoImpl struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &RepoImpl{
		DB: db,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}
