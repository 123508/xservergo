package service

import (
	"github.com/123508/xservergo/apps/file/repo"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type FileService interface {
	GetRedis() *redis.Client
	InitFileUpload(fileName, parentId string, fileSize uint64, fileMd5 string, targetUserId, requestUserId id.UUID) (chunkSize uint64, existingChunks []uint64, requestId string, err error)
}

type ServiceImpl struct {
	fileRepo repo.FileRepository
	Rds      *redis.Client
	Version  int
}

func NewService(database *gorm.DB, rds *redis.Client) FileService {
	return &ServiceImpl{
		fileRepo: repo.NewFileRepository(database),
		Rds:      rds,
		Version:  1,
	}
}

func (s *ServiceImpl) GetRedis() *redis.Client {
	return s.Rds
}

func (s *ServiceImpl) InitFileUpload(fileName, parentId string, fileSize uint64, fileMd5 string, targetUserId, requestUserId id.UUID) (chunkSize uint64, existingChunks []uint64, requestId string, err error) {
	//TODO implement me
	panic("implement me")
}
