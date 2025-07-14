package service

import (
	"context"
	"errors"
	"github.com/123508/xservergo/apps/user/repo"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"net/http"
)

type UserService interface {
	GetRedis() *redis.Client
	Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) error
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

func (s *ServiceImpl) Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) error {

	if u == nil || uLogin == nil {
		return cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	uid := util.NewUUID()

	u.ID = uid

	uLogin.UserID = u.ID

	uLogin.Password = Encryption(uLogin.Password)

	if err := s.userRepo.CreateUser(ctx, u, uLogin); err != nil {
		if errors.Is(err, &cerrors.SQLError{}) {
			return cerrors.NewCommonError(http.StatusInternalServerError, "用户注册失败", "", nil)
		} else if errors.Is(err, &cerrors.ParamError{}) {
			return cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
		}

		return cerrors.NewCommonError(http.StatusInternalServerError, "用户注册失败", "", err)
	}

	return nil
}
