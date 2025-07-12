package repo

import "gorm.io/gorm"

type AuthRepository interface {
	GetDB() *gorm.DB
}

type RepoImpl struct {
	DB *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &RepoImpl{
		DB: db,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}
