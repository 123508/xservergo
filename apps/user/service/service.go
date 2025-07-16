package service

import (
	"context"
	"errors"
	"github.com/123508/xservergo/apps/user/repo"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"net/http"
)

var authClient = cli.InitAuthService()

type UserService interface {
	GetRedis() *redis.Client
	Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) error
	EmailLogin(ctx context.Context, email, pwd string) (*models.User, *models.Token, error)
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

func (s *ServiceImpl) EmailLogin(ctx context.Context, email, pwd string) (*models.User, *models.Token, error) {

	if email == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByEmail(ctx, email)

	if err != nil {
		if errors.Is(err, &cerrors.SQLError{}) {
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
		}

		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", err)
	}

	if usr == nil {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户登录失败", "", nil)
	}

	ok, err := s.userRepo.ComparePassword(ctx, usr.ID, Encryption(pwd))
	if err != nil {
		if errors.Is(err, &cerrors.SQLError{}) {
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
		}
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", err)
	}

	if !ok {
		return &models.User{}, &models.Token{}, nil
	}

	resp, err := s.requestToken(ctx, usr.ID)

	if err != nil {
		return nil, nil, err
	}

	loginUsr := &models.User{
		NickName: usr.NickName,
		Email:    usr.Email,
		Avatar:   usr.Avatar,
	}

	return loginUsr, &models.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil

}

// 辅助函数(用于请求token)
func (s *ServiceImpl) requestToken(ctx context.Context, userId util.UUID) (*auth.IssueTokenResp, error) {

	marshal, err := userId.Marshal()

	if err != nil {
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "序列化参数错误", "", nil)
	}

	resp, err := authClient.IssueToken(ctx, &auth.IssueTokenReq{
		UserId: marshal,
	})

	if err != nil {
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
	}

	return resp, nil
}
