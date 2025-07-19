package service

import (
	"context"
	"github.com/123508/xservergo/apps/auth/repo"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/config"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"net/http"
	"time"
)

type AuthService interface {
	GetRedis() *redis.Client
	IssueToken(ctx context.Context, uid util.UUID) (models.Token, error)
	RefreshToken(ctx context.Context, token models.Token, uid util.UUID) (models.Token, error)
	VerifyToken(ctx context.Context, accessToken string) (util.UUID, []string, uint64, error)
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

func (s *ServiceImpl) IssueToken(ctx context.Context, uid util.UUID) (models.Token, error) {

	var perms []string
	accessToken, err := GenerateJWT(uid, perms, 0)

	if err != nil {
		logs.ErrorLogger.Error("生成accessToken错误:", zap.Error(err))
		return models.Token{}, cerrors.NewCommonError(http.StatusInternalServerError, "生成令牌错误", "", nil)
	}

	refreshToken, err := GenerateRefreshToken()

	if err != nil {
		logs.ErrorLogger.Error("生成refreshToken错误:", zap.Error(err))
		return models.Token{}, cerrors.NewCommonError(http.StatusInternalServerError, "生成令牌错误", "", nil)
	}

	if err = s.Rds.Set(ctx, refreshToken, true, 7*24*time.Hour).Err(); err != nil {
		return models.Token{}, cerrors.NewCommonError(http.StatusInternalServerError, "生成令牌错误", "", nil)
	}

	return models.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *ServiceImpl) RefreshToken(ctx context.Context, token models.Token, uid util.UUID) (models.Token, error) {
	if token.AccessToken == "" || token.RefreshToken == "" || uid.IsZero() {
		return models.Token{}, cerrors.NewParamError("请求参数错误")
	}

	if b, err := s.Rds.Get(ctx, token.RefreshToken).Bool(); err != nil || !b {
		return models.Token{}, cerrors.NewParamError("请求参数错误")
	}

	issueToken, err := s.IssueToken(ctx, uid)

	if err != nil {
		return models.Token{}, err
	}

	//原子化刷新令牌
	pipe := s.Rds.Pipeline()

	pipe.Set(ctx, token.RefreshToken, false, 7*24*time.Hour)

	pipe.Set(ctx, token.AccessToken, true, time.Duration(config.Conf.AdminTtl)*time.Second)

	_, err = pipe.Exec(ctx)

	if err != nil {
		return models.Token{}, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", "", nil)
	}

	return issueToken, nil
}

func (s *ServiceImpl) VerifyToken(ctx context.Context, accessToken string) (util.UUID, []string, uint64, error) {
	if accessToken == "" {
		return util.NewUUID(), nil, 0, cerrors.NewParamError("请求参数错误")
	}

	if b, err := s.Rds.Get(ctx, accessToken).Bool(); err == nil && b {
		return util.NewUUID(), nil, 0, cerrors.NewParamError("请求参数错误")
	}

	claims, err := ParseJWT(accessToken)

	if err != nil {
		return util.NewUUID(), nil, 0, cerrors.NewParamError("请求参数错误")
	}

	return claims.UserId, claims.Perms, claims.PVer, nil
}
