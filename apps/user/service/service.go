package service

import (
	"github.com/123508/xservergo/apps/user/repo"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type UserService interface {
	GetRedis() *redis.Client
}

type ServiceImpl struct {
	userRepo repo.UserRepository
	Rds      *redis.Client
}

func NewService(database *gorm.DB, rds *redis.Client) UserService {
	return &ServiceImpl{
		userRepo: repo.NewUserRepository(database),
		Rds:      rds,
	}
}

func (s *ServiceImpl) GetRedis() *redis.Client {
	return s.Rds
}
