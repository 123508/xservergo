package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

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
)

var authClient = cli.InitAuthService()

type UserService interface {
	GetRedis() *redis.Client
	Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) (err error)
	EmailLogin(ctx context.Context, email, pwd string) (userinfo *models.User, token *models.Token, err error)
	PhoneLogin(ctx context.Context, phone, pwd string) (userinfo *models.User, token *models.Token, err error)
	UserNameLogin(ctx context.Context, username, pwd string) (userinfo *models.User, token *models.Token, err error)
	SmsSendCode(ctx context.Context, phone string) (verifyCode string, err error)
	SmsLogin(ctx context.Context, phone, code, requestId string) (userinfo *models.User, token *models.Token, err error)
	SendPhoneCode(ctx context.Context, key, phone string) (err error)
	SendEmailCode(ctx context.Context, key, email string) (err error)
	GenerateQrCode(ctx context.Context, ip, userAgent string) (qrCode string, requestId string, expire uint64, err error)
	QrCodePreLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string) (ok bool, uid util.UUID, err error)
	QrCodeLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string, uid util.UUID) (status uint64, userinfo *models.User, token *models.Token, err error)
	QrPreLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (ok bool, err error)
	ConfirmQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (err error)
	CancelQrLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (err error)
	Logout(ctx context.Context, reqeustUid, targetUid util.UUID, token *models.Token) (err error)
	GetUserInfoById(ctx context.Context, targetUserId, requestUserId util.UUID) (userinfo *models.User, err error)
	GetUserInfoBySpecialSig(ctx context.Context, sign string, requestUserId util.UUID, queryType QueryType, serialType serializer.SerializerType) (userinfo *models.User, err error)
	ChangePassword(ctx context.Context, targetUserId, requestUserId util.UUID, oldPwd, newPwd string) (err error)
	ForgetPassword(ctx context.Context, sign string, queryType QueryType, serialType serializer.SerializerType, msgType uint64) (ok bool, uid util.UUID, requestId string, err error)
	ResetPassword(ctx context.Context, targetUserId, requestUserId util.UUID, newPwd, requestId, VerifyCode string) (err error)
	StartBindEmail(ctx context.Context, targetUserId, requestUserId util.UUID, newEmail string) (requestId string, err error)
	CompleteBindEmail(ctx context.Context, targetUserId, requestUserId util.UUID, newEmail, verifyCode, requestId string, version int) (v int, err error)
	StartBindPhone(ctx context.Context, targetUserId, requestUserId util.UUID, newPhone string) (requestId string, err error)
	CompleteBindPhone(ctx context.Context, targetUserId, requestUserId util.UUID, newPhone, verifyCode, requestId string, version int) (v int, err error)
	StartChangeEmail(ctx context.Context, targetUserId, requestUserId util.UUID) (requestId string, err error)
	VerifyNewEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, newEmail, RequestId string) (requestId string, err error)
	CompleteChangeEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, requestId string, version int) (v int, err error)
	StartChangePhone(ctx context.Context, targetUserId, requestUserId util.UUID) (requestId string, err error)
	VerifyNewPhone(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, newPhone, RequestId string) (requestId string, err error)
	CompleteChangePhone(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, requestId string, version int) (v int, err error)
	UpdateUserInfo(ctx context.Context, targetUserId, requestUserId util.UUID, nickName, avatar string, gender uint64, version int) (v int, err error)
	GetVersion(ctx context.Context, userId util.UUID) (v int, err error)
	AddVersion(ctx context.Context, userId util.UUID) (err error)
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

	if u == nil || uLogin == nil || u.Gender == 0 {
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

	return s.LoginWithResp(ctx, usr, pwd, err, true, "")

}

func (s *ServiceImpl) PhoneLogin(ctx context.Context, phone, pwd string) (*models.User, *models.Token, error) {
	if phone == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	return s.LoginWithResp(ctx, usr, pwd, err, true, "")
}

func (s *ServiceImpl) UserNameLogin(ctx context.Context, username, pwd string) (*models.User, *models.Token, error) {
	if username == "" || pwd == "" {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	usr, err := s.userRepo.GetUserByUsername(ctx, username)

	return s.LoginWithResp(ctx, usr, pwd, err, true, "")
}

func (s *ServiceImpl) SmsSendCode(ctx context.Context, phone string) (string, error) {

	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)

	if err != nil {
		return "", err
	}

	if err := s.Rds.Set(
		ctx,
		util.TakeKey("userservice", "user", "SmsLogin",
			phone,
		),
		true,
		10*time.Minute,
	).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", "", err)
	}

	SmsCodeToken := util.TakeKey("userservice", "user", "SmsLogin", "vCode", phone)

	if err := s.SendPhoneCode(ctx, SmsCodeToken, phone); err != nil {
		return "", err
	}

	return requestId, nil
}

func (s *ServiceImpl) SmsLogin(ctx context.Context, phone, code, requestId string) (*models.User, *models.Token, error) {

	//校验requestId
	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return nil, nil, err
	}

	//校验验证码
	res, err := s.Rds.Get(ctx, util.TakeKey("userservice", "user", "SmsLogin", "vCode", phone)).Result()

	if err != nil {
		return nil, nil, ParseRedisErr(err, requestId)
	}

	if res != code {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	resp, token, err := s.LoginWithResp(ctx, usr, "", err, false, requestId)

	//登录成功,删除凭证
	if err == nil {
		pipeline := s.Rds.Pipeline()

		pipeline.Del(ctx, util.TakeKey("userservice", "user", "vCode_Phone", phone))

		pipeline.Del(ctx, util.TakeKey("userservice", "user", "SmsLogin", phone))

		if _, err = pipeline.Exec(ctx); err != nil {
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", requestId, nil)
		}
	}

	return resp, token, err
}

func (s *ServiceImpl) GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64, error) {
	session := util.NewQRLoginSession(ip, userAgent, 5*time.Minute)
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

	requestId, err := s.GenerateRequestId(ctx, 5*time.Minute)

	if err != nil {
		return "", "", 0, err
	}

	return qrCode, requestId, uint64(time.Now().Add(5 * time.Minute).Unix()), nil
}

func (s *ServiceImpl) QrCodePreLoginStatus(
	ctx context.Context,
	ticket string,
	timeout uint64,
	requestId string,
) (bool, util.UUID, error) {

	//校验链路是否合法
	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return false, util.NewUUID(), err
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
	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return 6, nil, nil, err
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
		return status, nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "请求超时", requestId, nil)
	}

	//已取消状态
	if status == 5 {
		return status, nil, nil, nil
	}

	//校验成功状态
	usr, err := s.userRepo.GetUserByID(ctx, uid)

	usr, token, err := s.LoginWithResp(ctx, usr, "", err, false, requestId)

	if err != nil {
		return 6, nil, nil, err
	}

	return status, usr, token, nil
}

func (s *ServiceImpl) QrPreLogin(ctx context.Context, ticket string, uid util.UUID, requestId string) (bool, error) {

	//校验链路是否合法
	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return false, err
	}

	//校验二维码是否过期
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
		Key:       util.TakeKey("userservice", "user", "detail", "id", targetUserId.String()),
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
		Key:       util.TakeKey("userservice", "user", "detail", suffix, sign),
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

func (s *ServiceImpl) ForgetPassword(ctx context.Context, sign string, queryType QueryType, serialType serializer.SerializerType, msgType uint64) (bool, util.UUID, string, error) {

	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)

	if err != nil {
		return false, util.NewUUID(), "", err
	}

	usr, err := s.GetUserInfoBySpecialSig(ctx, sign, util.SystemUUID, queryType, serialType)
	if err != nil {
		return false, util.NewUUID(), "", err
	}

	ForgetToken := util.TakeKey("userserivce", "user", "forgetPassword", usr.ID)

	var Err error

	switch msgType {
	case 1:
		Err = s.SendEmailCode(ctx, ForgetToken, sign)
	default:
		Err = s.SendPhoneCode(ctx, ForgetToken, sign)
	}
	if Err != nil {
		return false, util.NewUUID(), "", Err
	}

	return true, usr.ID, requestId, nil
}

func (s *ServiceImpl) ResetPassword(ctx context.Context, targetUserId, requestUserId util.UUID, newPwd, requestId, VerifyCode string) error {

	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return err
	}

	//TODO权限校验部分

	ForgetToken := util.TakeKey("userserivce", "user", "forgetPassword", targetUserId)

	//校验验证码部分
	result, err := s.Rds.Get(ctx, ForgetToken).Result()

	if err != nil {
		return ParseRedisErr(err, requestId)
	}

	if result != VerifyCode {
		return cerrors.NewCommonError(http.StatusBadRequest, "更新失败,验证码错误", requestId, nil)
	}

	//更新密码
	if err := s.userRepo.UpdatePassword(ctx, targetUserId, Encryption(newPwd)); err != nil {
		return ParseRepoErrorToCommonError(err, "更新密码失败")
	} else {
		//移除凭证，使其只能使用一次
		s.Rds.Del(ctx, ForgetToken)
	}

	return nil
}

func (s *ServiceImpl) SendPhoneCode(ctx context.Context, key string, phone string) error {

	vCode := fmt.Sprintf("%06d", rand.Intn(1000000))

	//TODO 这里之后调用发送验证码的逻辑

	fmt.Printf("发送手机验证码:%s,手机号:%s\n", vCode, phone)

	if err := s.Rds.
		Set(ctx,
			key,
			vCode,
			10*time.Minute).
		Err(); err != nil {
		logs.ErrorLogger.Error("发送手机验证码错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "手机验证码发送错误", "", nil)
	}
	return nil
}

func (s *ServiceImpl) SendEmailCode(ctx context.Context, key string, email string) error {
	vCode := fmt.Sprintf("%06d", rand.Intn(1000000))

	//TODO 这里之后调用发送验证码的逻辑

	fmt.Printf("发送邮箱验证码:%s,邮箱:%s\n", vCode, email)

	if err := s.Rds.
		Set(ctx,
			key,
			vCode,
			10*time.Minute).
		Err(); err != nil {
		logs.ErrorLogger.Error("发送邮箱验证码错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "邮箱验证码发送错误", "", nil)
	}
	return nil
}

func (s *ServiceImpl) StartBindEmail(ctx context.Context, targetUserId, requestUserId util.UUID, newEmail string) (string, error) {

	//这里校验邮箱的合法性

	return s.StartBindPhoneOrEmail(ctx, targetUserId, requestUserId, newEmail, EMAIL)
}

func (s *ServiceImpl) CompleteBindEmail(ctx context.Context, targetUserId, requestUserId util.UUID, newEmail, verifyCode, requestId string, version int) (int, error) {
	return s.CompleteBindPhoneOrEmail(ctx, targetUserId, requestUserId, newEmail, verifyCode, requestId, version, EMAIL)
}

func (s *ServiceImpl) StartBindPhone(ctx context.Context, targetUserId, requestUserId util.UUID, newPhone string) (string, error) {

	//这里校验手机号的合法性

	return s.StartBindPhoneOrEmail(ctx, targetUserId, requestUserId, newPhone, PHONE)
}

func (s *ServiceImpl) CompleteBindPhone(ctx context.Context, targetUserId, requestUserId util.UUID, newPhone, verifyCode, requestId string, version int) (int, error) {
	return s.CompleteBindPhoneOrEmail(ctx, targetUserId, requestUserId, newPhone, verifyCode, requestId, version, PHONE)
}

func (s *ServiceImpl) StartChangeEmail(ctx context.Context, targetUserId, requestUserId util.UUID) (string, error) {
	return s.StartChangePhoneOrEmail(ctx, targetUserId, requestUserId, EMAIL)
}

func (s *ServiceImpl) VerifyNewEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, newEmail, requestId string) (string, error) {
	return s.VerifyNewPhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, newEmail, requestId, EMAIL)
}

func (s *ServiceImpl) CompleteChangeEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, requestId string, version int) (v int, err error) {
	return s.CompleteChangePhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, requestId, version, EMAIL)
}

func (s *ServiceImpl) StartChangePhone(ctx context.Context, targetUserId, requestUserId util.UUID) (string, error) {
	return s.StartChangePhoneOrEmail(ctx, targetUserId, requestUserId, PHONE)
}

func (s *ServiceImpl) VerifyNewPhone(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, newPhone, requestId string) (string, error) {
	return s.VerifyNewPhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, newPhone, requestId, PHONE)
}

func (s *ServiceImpl) CompleteChangePhone(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, requestId string, version int) (v int, err error) {
	return s.CompleteChangePhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, requestId, version, PHONE)
}

func (s *ServiceImpl) UpdateUserInfo(ctx context.Context, targetUserId, requestUserId util.UUID, nickName, avatar string, gender uint64, version int) (int, error) {

	usr, err := s.GetUserInfoById(ctx, targetUserId, requestUserId)
	if err != nil {
		return version, err
	}

	usr.NickName = nickName
	usr.Avatar = avatar
	usr.Gender = gender

	v, err := s.userRepo.UpdateUser(ctx, usr, requestUserId)

	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器错误")
	}

	s.CleanCache(ctx, usr)

	return v, nil
}

func (s *ServiceImpl) GetVersion(ctx context.Context, userId util.UUID) (v int, err error) {
	usr, err := s.userRepo.GetUserByID(ctx, userId)
	if err != nil {
		return 0, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	s.Rds.Set(ctx, util.TakeKey("userservice", "user", "version", userId), *usr.Version, 7*time.Hour)

	return *usr.Version, nil
}

func (s *ServiceImpl) AddVersion(ctx context.Context, userId util.UUID) (err error) {
	if err = s.userRepo.AddVersion(ctx, userId); err != nil {
		return ParseRepoErrorToCommonError(err, "服务器异常")
	}
	defer s.Rds.Del(ctx, util.TakeKey("userservice", "user", "version", userId))
	return nil
}

func (s *ServiceImpl) ConfirmOrCancelQrLogin(
	ctx context.Context,
	ticket string,
	uid util.UUID,
	requestId string,
	status int,
) error {
	//校验链路是否合法
	if err := s.VerityRequestID(ctx, requestId); err != nil {
		return err
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

func (s *ServiceImpl) StartBindPhoneOrEmail(ctx context.Context, targetUserId, requestUserId util.UUID, sign string, form QueryType) (string, error) {
	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)
	if err != nil {
		return "", err
	}

	switch form {
	case PHONE:
		phoneToken := util.TakeKey("userserivce", "user", "StartBindPhone", sign, targetUserId)
		if err = s.SendPhoneCode(ctx, phoneToken, sign); err != nil {
			return "", err
		}
	case EMAIL:
		emailToken := util.TakeKey("userserivce", "user", "StartBindEmail", sign, targetUserId)
		if err = s.SendEmailCode(ctx, emailToken, sign); err != nil {
			return "", err
		}
	default:
		return "", cerrors.NewCommonError(http.StatusBadRequest, "请求类型错误", "", nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) CompleteBindPhoneOrEmail(ctx context.Context, targetUserId, requestUserId util.UUID, sign, verifyCode, requestId string, version int, form QueryType) (v int, err error) {
	//请求用户
	usr, err := s.userRepo.GetUserByID(ctx, targetUserId)
	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	//CAS校验
	if *usr.Version != version {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "令牌过期,请使用新令牌", requestId, nil)
	}

	//鉴权

	defer s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "id", targetUserId))
	switch form {
	case EMAIL:
		defer s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "phone", usr.Phone))
	case PHONE:
		defer s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "email", usr.Email))
	}

	var Token string

	switch form {
	case EMAIL:
		Token = util.TakeKey("userserivce", "user", "StartBindEmail", sign, targetUserId)
	case PHONE:
		Token = util.TakeKey("userserivce", "user", "StartBindPhone", sign, targetUserId)
	default:
		return version, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	//获取验证码
	code, err := s.Rds.Get(ctx, Token).Result()
	//获取验证码失败
	if err != nil {
		return version, ParseRedisErr(err, requestId)
	}

	//校验验证码
	if code != verifyCode {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	switch form {
	case EMAIL:
		//重置邮箱
		v, err = s.userRepo.ResetEmail(ctx, targetUserId, sign, version, requestUserId)
	case PHONE:
		//重置手机号
		v, err = s.userRepo.ResetPhone(ctx, targetUserId, sign, version, requestUserId)

	default:
		return version, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器错误")
	}

	//删除临时凭证
	s.Rds.Del(ctx, Token)
	//删除缓存
	s.CleanCache(ctx, usr)
	//更新版本号
	s.AddVersion(ctx, usr.ID)

	return v, nil
}

func (s *ServiceImpl) StartChangePhoneOrEmail(ctx context.Context, targetUserId, requestUserId util.UUID, form QueryType) (requestId string, err error) {

	//生成requestId
	requestId, err = s.GenerateRequestId(ctx, 10*time.Minute)
	if err != nil {
		return "", err
	}

	//获取用户信息
	usr, err := s.GetUserInfoById(ctx, targetUserId, requestUserId)

	if err != nil {
		return "", err
	}

	//发送验证码
	switch form {
	case PHONE:
		if usr.Phone == "" {
			return "", cerrors.NewCommonError(http.StatusForbidden, "请先绑定手机号", "", nil)
		}
		phoneToken := util.TakeKey("userserivce", "user", "StartChangePhone", usr.Phone, targetUserId)
		if err := s.SendPhoneCode(ctx, phoneToken, usr.Phone); err != nil {
			return "", err
		}
	case EMAIL:
		if usr.Email == "" {
			return "", cerrors.NewCommonError(http.StatusForbidden, "请先绑定邮箱", "", nil)
		}
		emailToken := util.TakeKey("userserivce", "user", "StartChangeEmail", usr.Email, targetUserId)
		if err := s.SendEmailCode(ctx, emailToken, usr.Phone); err != nil {
			return "", err
		}
	default:
		return "", cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) VerifyNewPhoneOrEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, sign, RequestId string, form QueryType) (requestId string, err error) {
	//校验requestId
	if err = s.VerityRequestID(ctx, RequestId); err != nil {
		return "", err
	}

	//获取用户信息(因为前面有缓存这次查询可以接受)
	usr, err := s.GetUserInfoById(ctx, targetUserId, requestUserId)
	if err != nil {
		return requestId, err
	}

	//请求验证码
	var Token string

	switch form {
	case PHONE:
		Token = util.TakeKey("userserivce", "user", "StartChangePhone", usr.Phone, targetUserId)
	case EMAIL:
		Token = util.TakeKey("userserivce", "user", "StartChangeEmail", usr.Email, targetUserId)
	default:
		return requestId, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	result, err := s.Rds.Get(ctx, Token).Result()
	if err != nil {
		return requestId, ParseRedisErr(err, requestId)
	}

	//验证码错误
	if result != verifyCode {
		return requestId, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	var storeToken string

	//向新邮箱/手机号请求验证码
	switch form {
	case PHONE:
		newPhoneToken := util.TakeKey("userserivce", "user", "ReChangePhone", targetUserId)
		if err := s.SendPhoneCode(ctx, newPhoneToken, sign); err != nil {
			return requestId, err
		}
		storeToken = util.TakeKey("userservice", "user", "ReChangePhone", "newPhone", targetUserId)
	case EMAIL:
		newEmailToken := util.TakeKey("userserivce", "user", "ReChangeEmail", targetUserId)
		if err := s.SendEmailCode(ctx, newEmailToken, sign); err != nil {
			return requestId, err
		}
		storeToken = util.TakeKey("userservice", "user", "ReChangePhone", "newEmail", targetUserId)
	default:
		return requestId, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	//存储新sign
	if err := s.Rds.Set(
		ctx,
		storeToken,
		sign,
		13*time.Minute).Err(); err != nil {
		return requestId, ParseRedisErr(err, requestId)
	}

	//删除临时凭证
	s.Rds.Del(ctx, Token)

	return requestId, nil
}

func (s *ServiceImpl) CompleteChangePhoneOrEmail(ctx context.Context, targetUserId, requestUserId util.UUID, verifyCode, requestId string, version int, form QueryType) (v int, err error) {

	//请求用户
	usr, err := s.userRepo.GetUserByID(ctx, targetUserId)
	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	//CAS校验
	if *usr.Version != version {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "令牌过期,请使用新令牌", requestId, nil)
	}

	if err = s.VerityRequestID(ctx, requestId); err != nil {
		return version, err
	}

	var Token string

	switch form {
	case PHONE:
		Token = util.TakeKey("userserivce", "user", "ReChangePhone", targetUserId)
	case EMAIL:
		Token = util.TakeKey("userserivce", "user", "ReChangeEmail", targetUserId)
	default:
		return version, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	result, err := s.Rds.Get(ctx, Token).Result()
	if err != nil {
		return version, ParseRedisErr(err, requestId)
	}

	//验证码错误
	if result != verifyCode {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	//获取新传入的手机号/邮箱
	var storeToken string

	switch form {
	case PHONE:
		storeToken = util.TakeKey("userservice", "user", "ReChangePhone", "newPhone", targetUserId)
	case EMAIL:
		storeToken = util.TakeKey("userservice", "user", "ReChangePhone", "newEmail", targetUserId)
	default:
		return version, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	sign, err := s.Rds.Get(ctx, storeToken).Result()

	if err != nil {
		return version, ParseRedisErr(err, requestId)
	}

	//修改数据
	switch form {
	case PHONE:
		v, err = s.userRepo.ResetPhone(ctx, targetUserId, sign, version, requestUserId)
	case EMAIL:
		v, err = s.userRepo.ResetEmail(ctx, targetUserId, sign, version, requestUserId)
	default:
		return version, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	//删除临时凭证
	s.Rds.Del(ctx, Token)
	//删除缓存
	s.CleanCache(ctx, usr)
	//删除临时存储的新sign
	s.Rds.Del(ctx, storeToken)
	//更新版本号
	s.AddVersion(ctx, usr.ID)

	return v, nil
}

// LoginWithResp 辅助函数(用于用户登录)
func (s *ServiceImpl) LoginWithResp(
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
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "获取用户失败", requestId, nil)
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
	resp, err := s.RequestToken(ctx, usr.ID, *usr.Version)

	if err != nil {
		return nil, nil, err
	}

	loginUsr := &models.User{
		ID:       usr.ID,
		UserName: usr.UserName,
		NickName: usr.NickName,
		Email:    usr.Email,
		Avatar:   usr.Avatar,
		Gender:   usr.Gender,
		Phone:    usr.Phone,
	}

	return loginUsr, &models.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil

}

// RequestToken 辅助函数(用于请求token)
func (s *ServiceImpl) RequestToken(ctx context.Context, userId util.UUID, version int) (*auth.IssueTokenResp, error) {

	marshal := userId.MarshalBase64()

	resp, err := authClient.IssueToken(ctx, &auth.IssueTokenReq{
		UserId: marshal,
	})

	if err != nil {
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "用户登录失败", "", nil)
	}

	return resp, nil
}

func (s *ServiceImpl) GenerateRequestId(ctx context.Context, expire time.Duration) (string, error) {
	requestId := uuid.New().String()
	if err := s.Rds.Set(ctx, util.TakeKey("userservice", "user", "requestId", requestId), "ok", expire).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "生产requestId失败", "", err)
	}
	return requestId, nil
}

func (s *ServiceImpl) VerityRequestID(ctx context.Context, requestId string) error {

	token := util.TakeKey("userservice", "user", "requestId", requestId)
	//校验requestId
	result, err := s.Rds.Get(ctx, token).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis查询requestId错误", requestId, nil)
	} else if result != "ok" || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "requestId过期", requestId, nil)
	}
	//刷新过期时间
	s.Rds.Expire(ctx, token, 10*time.Minute)
	return nil
}

func (s *ServiceImpl) CleanCache(ctx context.Context, usr *models.User) {
	s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "id", usr.ID.String()))
	s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "username", usr.UserName))
	s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "email", usr.Email))
	s.Rds.Del(ctx, util.TakeKey("userservice", "user", "detail", "phone", usr.Phone))
}
