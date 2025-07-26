package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/123508/xservergo/apps/user/repo"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/component/serializer"
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
	GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64, error)
	QrCodePreLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string) (bool, util.UUID, error)
	QrCodeLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string, uid util.UUID) (uint64, *models.User, *models.Token, error)
	QrPreLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (bool, error)
	ConfirmQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) error
	CancelQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) error
	Logout(ctx context.Context, reqeustUid, targetUid util.UUID, token *models.Token) error
	GetUserInfoById(ctx context.Context, targetUserId, requestUserId util.UUID) (*models.User, error)
	GetUserInfoBySpecialSig(ctx context.Context, sign string, requestUserId util.UUID, queryType QueryType, serialType serializer.SerializerType) (*models.User, error)
	ChangePassword(ctx context.Context, targetUserId, requestUserId util.UUID, oldPwd, newPwd string) error
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
		return ParseRepoErrorToCommonError(err, "用户注册失败")
	}

	return nil
}

func (s *ServiceImpl) EmailLogin(ctx context.Context, email, pwd string) (*models.User, *models.Token, error) {

	if email == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByEmail(ctx, email)

	return s.loginWithResp(ctx, usr, pwd, err, true, "")

}

func (s *ServiceImpl) PhoneLogin(ctx context.Context, phone, pwd string) (*models.User, *models.Token, error) {
	if phone == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	return s.loginWithResp(ctx, usr, pwd, err, true, "")
}

func (s *ServiceImpl) UserNameLogin(ctx context.Context, username, pwd string) (*models.User, *models.Token, error) {
	if username == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByUsername(ctx, username)

	return s.loginWithResp(ctx, usr, pwd, err, true, "")
}

func (s *ServiceImpl) SmsSendCode(ctx context.Context, phone string) (string, error) {

	requestId := uuid.New().String()

	pipeline := s.Rds.Pipeline()

	pipeline.Set(ctx, util.TakeKey("userservice", "user", "SmsLogin", phone), true, 10*time.Minute)

	pipeline.Set(ctx, util.TakeKey("common", "requestId", requestId), "ok", 10)

	if _, err := pipeline.Exec(ctx); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", "", nil)
	}

	if err := s.SendPhoneCode(ctx, phone); err != nil {
		return "", err
	}

	return requestId, nil
}

func (s *ServiceImpl) SmsLogin(ctx context.Context, phone, code, requestId string) (*models.User, *models.Token, error) {

	//校验requestId
	result, err := s.Rds.Get(ctx, util.TakeKey("common", "requestId", requestId)).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	} else if result != "ok" || errors.Is(err, redis.Nil) {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}

	//校验验证码
	res, err := s.Rds.Get(ctx, util.TakeKey("userservice", "user", "vCode_Phone", phone)).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "验证码过期", requestId, nil)
		}
		return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", requestId, nil)
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

	return s.loginWithResp(ctx, usr, "", err, false, requestId)
}

func (s *ServiceImpl) GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64, error) {
	session := util.NewQRLoginSession(ip, userAgent, 5*time.Second)
	_, qrCode, err := session.GenerateQR(50, "H")
	if err != nil {
		return "", "", 0, cerrors.NewCommonError(http.StatusInternalServerError, "生成二维码错误", "", err)
	}

	if err = s.Rds.Set(ctx,
		util.TakeKey("userservice", "user", "qrLogin", session.UniqueSig),
		1,
		5*time.Minute,
	).Err(); err != nil {
		return "", "", 0, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", "", err)
	}

	requestId := uuid.New().String()

	if err = s.Rds.Set(
		ctx,
		util.TakeKey("userservice", "user", "requestId", requestId),
		"ok",
		5*time.Minute,
	).Err(); err != nil {
		return "", "", 0, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", "", err)
	}

	return qrCode, requestId, uint64(time.Now().Add(5 * time.Second).Unix()), nil
}

func (s *ServiceImpl) QrCodePreLoginStatus(
	ctx context.Context,
	ticket string,
	timeout uint64,
	requestId string,
) (bool, util.UUID, error) {

	//校验链路是否合法
	requestIdToken := util.TakeKey("common", "requestId", requestId)

	ok, err := s.Rds.Get(ctx, requestIdToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return false, util.NewUUID(), cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if ok != "ok" || errors.Is(err, redis.Nil) {
		return false, util.NewUUID(), cerrors.NewCommonError(http.StatusInternalServerError, "请求无效", requestId, err)
	}

	//获取uid
	takeUidToken := util.TakeKey("userservice", "user", "takeUid", ticket)

	expireTime := time.Now().Add(time.Duration(timeout) * time.Second).Unix()

	if timeout < 10 || timeout > 600 {
		expireTime = time.Now().Add(time.Duration(30) * time.Second).Unix()
	}

	uid := util.NewUUID()

	isOk := false

	for time.Now().Unix() <= expireTime {
		result, err := s.Rds.Get(ctx, takeUidToken).Result()

		if err != nil && !errors.Is(err, redis.Nil) {
			return false, util.NewUUID(), cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
		}

		uid, err = util.FromString(result)

		if err == nil {
			isOk = true
			break
		}

		time.Sleep(time.Second)
	}

	if !isOk {
		return false, util.NewUUID(), cerrors.NewCommonError(http.StatusNotAcceptable, "请求超时", requestId, nil)
	}

	return true, uid, nil
}

func (s *ServiceImpl) QrCodeLoginStatus(
	ctx context.Context,
	ticket string,
	timeout uint64,
	requestId string,
	uid util.UUID,
) (uint64, *models.User, *models.Token, error) {

	//校验链路是否合法
	requestIdToken := util.TakeKey("common", "requestId", requestId)

	ok, err := s.Rds.Get(ctx, requestIdToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return 6, nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if ok != "ok" || errors.Is(err, redis.Nil) {
		return 6, nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "请求无效", requestId, err)
	}

	//校验ticket
	ticketToken := util.TakeKey("userservice", "user", "qrLogin", ticket)

	expireTime := time.Now().Add(time.Duration(timeout) * time.Second).Unix()

	if timeout < 10 || timeout > 600 {
		expireTime = time.Now().Add(time.Duration(30) * time.Second).Unix()
	}

	var status uint64 = 4

	for time.Now().Unix() <= expireTime {
		result, err := s.Rds.Get(ctx, ticketToken).Result()

		if err != nil && !errors.Is(err, redis.Nil) {
			return 6, nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
		}

		if result == "3" {
			status = 3
			break
		} else if result == "5" {
			status = 5
			break
		}

		time.Sleep(time.Second)
	}

	//超时响应
	if status == 4 {
		return status, nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求超时", requestId, err)
	}

	//已取消状态
	if status == 5 {
		return status, nil, nil, nil
	}

	//校验成功状态
	usr, err := s.userRepo.GetUserByID(ctx, uid)

	usr, token, err := s.loginWithResp(ctx, usr, "", err, false, requestId)

	if err != nil {
		return 6, nil, nil, err
	}

	return status, usr, token, nil
}

func (s *ServiceImpl) QrPreLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (bool, error) {

	//校验链路是否合法
	requestIdToken := util.TakeKey("common", "requestId", requestId)

	ok, err := s.Rds.Get(ctx, requestIdToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return false, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if ok != "ok" || errors.Is(err, redis.Nil) {
		return false, cerrors.NewCommonError(http.StatusInternalServerError, "请求无效", requestId, err)
	}

	//教研二维码是否过期
	ticketToken := util.TakeKey("userservice", "user", "qrLogin", ticket)

	result, err := s.Rds.Get(ctx, ticketToken).Result()

	if err != nil {
		return false, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if result != "1" || errors.Is(err, redis.Nil) {
		return false, cerrors.NewCommonError(http.StatusBadRequest, "二维码过期", requestId, err)
	}

	//原子操作
	pipe := s.Rds.Pipeline()

	//续期ticketToken
	pipe.Expire(ctx, ticketToken, 5*time.Minute)

	//写入通过ticket获取uid
	takeUidToken := util.TakeKey("userservice", "user", "takeUid", ticket)

	pipe.Set(ctx, takeUidToken, uid.String(), 5*time.Minute)

	if _, err = pipe.Exec(ctx); err != nil {
		return false, cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	}

	return true, nil
}

func (s *ServiceImpl) ConfirmQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) error {
	return s.ConfirmOrCancelQrLogin(ctx, ticket, uid, requestId, 3)
}

func (s *ServiceImpl) CancelQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) error {
	return s.ConfirmOrCancelQrLogin(ctx, ticket, uid, requestId, 5)
}

func (s *ServiceImpl) ConfirmOrCancelQrLogin(
	ctx context.Context,
	ticket string,
	uid util.UUID,
	requestId string,
	status int,
) error {
	//校验链路是否合法
	requestIdToken := util.TakeKey("common", requestId)

	ok, err := s.Rds.Get(ctx, requestIdToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if ok != "ok" || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "请求无效", requestId, err)
	}

	//校验上下文用户是否为同一个人
	takeUidToken := util.TakeKey("userservice", "user", "takeUid", ticket)

	result, err := s.Rds.Get(ctx, takeUidToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if result != uid.String() || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "用户错误,不允许的操作", requestId, err)
	}

	//重置ticket状态
	ticketToken := util.TakeKey("userservice", "user", "qrLogin", ticket)

	if err = s.Rds.Set(ctx, ticketToken, status, 5*time.Minute).Err(); err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	}

	return nil
}

func (s *ServiceImpl) Logout(ctx context.Context, reqeustUid, targetUid util.UUID, token *models.Token) error {

	//权限校验

	//业务代码
	if token == nil {
		return cerrors.NewCommonError(http.StatusBadRequest, "请求错误", "", nil)
	}

	pipe := s.Rds.Pipeline()

	pipe.Set(ctx, util.TakeKey("user_token_used", "refresh", token.RefreshToken), true, 7*24*time.Hour)

	pipe.Set(ctx, util.TakeKey("user_token_used", "access", token.AccessToken), true, 7*24*time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetUserInfoById(ctx context.Context, targetUserId, requestUserId util.UUID) (*models.User, error) {

	if targetUserId.IsZero() || requestUserId.IsZero() {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil)
	}

	wrapper := serializer.NewSerializerWrapper(serializer.JSON)

	simple := util.SimpleCacheComponent[util.UUID, *models.User]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       util.TakeKey(util.TakeKey("userservice", "user", "detail", "id", targetUserId.String())),
		Marshal:   wrapper.Serialize,
		Unmarshal: wrapper.Deserialize,
		QueryExec: func() (*models.User, error) {
			return s.userRepo.GetUserByID(ctx, targetUserId)
		},
		Expires: 30 * time.Minute,
		Random:  time.Duration(rand.Intn(5)) * time.Minute,
	}

	usr, err := simple.QueryWithCache()

	if err != nil {
		return nil, ParseRepoErrorToCommonError(err, "未知异常")
	}

	if usr == nil {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "用户不存在或者已经删除", "", nil)
	}

	return &models.User{
		ID:       usr.ID,
		NickName: usr.NickName,
		UserName: usr.UserName,
		Email:    usr.Email,
		Phone:    usr.Phone,
		Gender:   usr.Gender,
		Avatar:   usr.Avatar,
	}, nil

}

func (s *ServiceImpl) GetUserInfoBySpecialSig(ctx context.Context, sign string, requestUserId util.UUID, queryType QueryType, serialType serializer.SerializerType) (*models.User, error) {

	if sign == "" || requestUserId.IsZero() {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil)
	}

	var suffix string

	switch queryType {
	case PHONE:
		suffix = "phone"
	case EMAIL:
		suffix = "email"
	case USERNAME:
		suffix = "username"
	default:
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil)
	}

	wrapper := serializer.NewSerializerWrapper(serialType)

	simple := util.SimpleCacheComponent[util.UUID, *models.User]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       util.TakeKey(util.TakeKey("userservice", "user", "detail", suffix, sign)),
		Marshal:   wrapper.Serialize,
		Unmarshal: wrapper.Deserialize,
		QueryExec: func() (*models.User, error) {
			switch queryType {
			case PHONE:
				return s.userRepo.GetUserByPhone(ctx, sign)
			case EMAIL:
				return s.userRepo.GetUserByEmail(ctx, sign)
			case USERNAME:
				return s.userRepo.GetUserByUsername(ctx, sign)
			}
			return nil, cerrors.NewParamError(http.StatusBadRequest, "传递字段错误")
		},
		Expires: 30 * time.Minute,
		Random:  time.Duration(rand.Intn(5)) * time.Minute,
	}

	usr, err := simple.QueryWithCache()

	if err != nil {
		return nil, ParseRepoErrorToCommonError(err, "未知异常")
	}

	if usr == nil {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "用户不存在或者已经删除", "", nil)
	}

	return &models.User{
		ID:       usr.ID,
		NickName: usr.NickName,
		UserName: usr.UserName,
		Email:    usr.Email,
		Phone:    usr.Phone,
		Gender:   usr.Gender,
		Avatar:   usr.Avatar,
	}, nil

}

func (s *ServiceImpl) ChangePassword(ctx context.Context, targetUserId, requestUserId util.UUID, oldPwd, newPwd string) error {

	ok, err := s.userRepo.ComparePassword(ctx, targetUserId, Encryption(oldPwd))

	if err != nil {
		return ParseRepoErrorToCommonError(err, "修改失败")
	}

	if !ok {
		return cerrors.NewCommonError(http.StatusBadRequest, "旧密码错误", "", nil)
	}

	if err := s.userRepo.UpdatePassword(ctx, targetUserId, Encryption(newPwd)); err != nil {
		return ParseRepoErrorToCommonError(err, "修改失败")
	}

	return nil
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
func (s *ServiceImpl) loginWithResp(
	ctx context.Context,
	usr *models.User,
	pwd string,
	err error,
	hasPwd bool,
	requestId string,
) (*models.User, *models.Token, error) {

	//错误处理部分
	if err != nil {
		return nil, nil, ParseRepoErrorToCommonError(err, "用户登录失败")
	}

	if usr == nil {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户登录失败", requestId, nil)
	}

	if hasPwd {
		//校验密码部分
		ok, err := s.userRepo.ComparePassword(ctx, usr.ID, Encryption(pwd))
		if err != nil {
			//错误处理部分
			return nil, nil, ParseRepoErrorToCommonError(err, "用户登录失败")
		}

		if !ok {
			return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户名或者密码错误", requestId, nil)
		}
	}

	if usr.Status == 1 {
		return nil, nil, cerrors.NewCommonError(http.StatusNotAcceptable, "用户已被冻结", requestId, nil)
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
