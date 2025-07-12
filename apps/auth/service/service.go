package service

import (
	"github.com/123508/xservergo/apps/auth/repo"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type AuthService interface {
	GetRedis() *redis.Client
}

type ServiceImpl struct {
	authRepo repo.AuthRepository
	Rds      *redis.Client
}

func NewService(database *gorm.DB, rds *redis.Client) AuthService {
	return &ServiceImpl{
		authRepo: repo.NewAuthRepository(database),
		Rds:      rds,
	}
}

func (s *ServiceImpl) GetRedis() *redis.Client {
	return s.Rds
}
