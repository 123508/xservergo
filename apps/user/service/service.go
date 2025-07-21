package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/123508/xservergo/apps/user/repo"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"math/rand"
	"net/http"
	"time"
)

var authClient = cli.InitAuthService()

type UserService interface {
	GetRedis() *redis.Client
	Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) error
	EmailLogin(ctx context.Context, email, pwd string) (*models.User, *models.Token, error)
	PhoneLogin(ctx context.Context, phone, pwd string) (*models.User, *models.Token, error)
	UserNameLogin(ctx context.Context, username, pwd string) (*models.User, *models.Token, error)
	SmsSendCode(ctx context.Context, phone string) (string, error)
	SmsLogin(ctx context.Context, phone, code, requestId string) (*models.User, *models.Token, error)
	SendPhoneCode(ctx context.Context, phone string) error
	SendEmailCode(ctx context.Context, email string) error
	GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64)
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

	return s.loginWithResp(ctx, usr, pwd, err, true)

}

func (s *ServiceImpl) PhoneLogin(ctx context.Context, phone, pwd string) (*models.User, *models.Token, error) {
	if phone == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	return s.loginWithResp(ctx, usr, pwd, err, true)
}

func (s *ServiceImpl) UserNameLogin(ctx context.Context, username, pwd string) (*models.User, *models.Token, error) {
	if username == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByUsername(ctx, username)

	return s.loginWithResp(ctx, usr, pwd, err, true)
}

func (s *ServiceImpl) SmsSendCode(ctx context.Context, phone string) (string, error) {

	requestId := uuid.New().String()

	if err := s.Rds.
		Set(ctx,
			util.TakeKey("userservice", "user", "SmsLogin", phone),
			requestId,
			10*time.Minute).
		Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", "", nil)
	}

	if err := s.SendPhoneCode(ctx, phone); err != nil {
		return "", err
	}

	return requestId, nil
}

func (s *ServiceImpl) SmsLogin(ctx context.Context, phone, code, requestId string) (*models.User, *models.Token, error) {

	//校验requestId
	result, err := s.Rds.Get(ctx, util.TakeKey("userservice", "user", "SmsLogin", phone)).Result()

	if err != nil {
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	}

	if result == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}

	if result != requestId {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "requestId错误", requestId, nil)
	}

	//校验验证码
	res, err := s.Rds.Get(ctx, util.TakeKey("userservice", "user", "vCode_Phone", phone)).Result()

	if err != nil {
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", requestId, nil)
	}

	if res == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "验证码过期", requestId, nil)
	}

	if res != code {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	pipeline := s.Rds.Pipeline()

	pipeline.Del(ctx, util.TakeKey("userservice", "user", "vCode_Phone", phone))

	pipeline.Del(ctx, util.TakeKey("userservice", "user", "SmsLogin", phone))

	_, err = pipeline.Exec(ctx)

	if err != nil {
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", requestId, nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	return s.loginWithResp(ctx, usr, "", err, false)
}

func (s *ServiceImpl) GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64) {
	//TODO implement me
	panic("implement me")
}

func (s *ServiceImpl) SendPhoneCode(ctx context.Context, phone string) error {

	vCode := fmt.Sprintf("%06d", rand.Intn(1000000))

	//TODO 这里之后调用发送验证码的逻辑

	fmt.Println("发送手机验证码:", vCode)

	if err := s.Rds.
		Set(ctx,
			util.TakeKey("userservice", "user", "vCode_Phone", phone),
			vCode,
			10*time.Minute).
		Err(); err != nil {
		logs.ErrorLogger.Error("发送手机验证码错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "手机验证码发送错误", "", nil)
	}
	return nil
}

func (s *ServiceImpl) SendEmailCode(ctx context.Context, email string) error {
	vCode := fmt.Sprintf("%06d", rand.Intn(1000000))

	//TODO 这里之后调用发送验证码的逻辑

	fmt.Println("发送邮箱验证码:", vCode)

	if err := s.Rds.
		Set(ctx,
			util.TakeKey("userservice", "user", "vCode_Email", email),
			vCode,
			10*time.Minute).
		Err(); err != nil {
		logs.ErrorLogger.Error("发送邮箱验证码错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "邮箱验证码发送错误", "", nil)
	}
	return nil
}

// 辅助函数(用于用户登录)
func (s *ServiceImpl) loginWithResp(ctx context.Context, usr *models.User, pwd string, err error, hasPwd bool) (*models.User, *models.Token, error) {

	//错误处理部分
	if err != nil {
		if errors.Is(err, &cerrors.SQLError{}) {
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
		}

		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", err)
	}

	if usr == nil {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户登录失败", "", nil)
	}

	if hasPwd {
		//校验密码部分
		ok, err := s.userRepo.ComparePassword(ctx, usr.ID, Encryption(pwd))
		if err != nil {
			if errors.Is(err, &cerrors.SQLError{}) {
				return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
			}
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", err)
		}

		if !ok {
			return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户名或者密码错误", "", nil)
		}
	}

	//获取token部分
	resp, err := s.requestToken(ctx, usr.ID)

	if err != nil {
		return nil, nil, err
	}

	loginUsr := &models.User{
		ID:       usr.ID,
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
