package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	serializer2 "github.com/123508/xservergo/pkg/util/component/serializer"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/123508/xservergo/pkg/util/qr"
	"github.com/123508/xservergo/pkg/util/urds"

	"github.com/123508/xservergo/apps/user/repo"
	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var authClient = cli.InitAuthService()

type UserService interface {
	GetRedis() *redis.Client
	Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) (err error, requestId string)
	EmailLogin(ctx context.Context, email, pwd string) (userinfo *models.User, token *models.Token, err error, requestId string)
	PhoneLogin(ctx context.Context, phone, pwd string) (userinfo *models.User, token *models.Token, err error, requestId string)
	UserNameLogin(ctx context.Context, username, pwd string) (userinfo *models.User, token *models.Token, err error, requestId string)
	SmsSendCode(ctx context.Context, phone string) (verifyCode string, err error)
	SmsLogin(ctx context.Context, phone, code, requestId string) (userinfo *models.User, token *models.Token, err error)
	SendPhoneCode(ctx context.Context, key, phone string) (err error)
	SendEmailCode(ctx context.Context, key, email string) (err error)
	GenerateQrCode(ctx context.Context, ip, userAgent string) (qrCode string, requestId string, expire uint64, err error)
	QrCodePreLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string) (ok bool, uid id.UUID, err error)
	QrCodeLoginStatus(ctx context.Context, ticket string, timeout uint64, requestId string, uid id.UUID) (status uint64, userinfo *models.User, token *models.Token, err error)
	QrPreLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) (err error)
	ConfirmQrLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) (err error)
	CancelQrLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) (err error)
	Logout(ctx context.Context, reqeustUid, targetUid id.UUID, token *models.Token) (err error, requestId string)
	GetUserInfoById(ctx context.Context, targetUserId, requestUserId id.UUID) (userinfo *models.User, err error, requestId string)
	GetUserInfoBySpecialSig(ctx context.Context, sign string, requestUserId id.UUID, queryType QueryType, serialType serializer2.SerializerType) (userinfo *models.User, err error, requestId string)
	ChangePassword(ctx context.Context, targetUserId, requestUserId id.UUID, oldPwd, newPwd string) (err error, requestId string)
	ForgetPassword(ctx context.Context, sign string, queryType QueryType, serialType serializer2.SerializerType, msgType uint64) (uid id.UUID, requestId string, err error)
	ResetPassword(ctx context.Context, targetUserId, requestUserId id.UUID, newPwd, requestId, VerifyCode string) (err error)
	StartBindEmail(ctx context.Context, targetUserId, requestUserId id.UUID, newEmail string) (requestId string, err error)
	CompleteBindEmail(ctx context.Context, targetUserId, requestUserId id.UUID, newEmail, verifyCode, requestId string, version int) (v int, err error)
	StartBindPhone(ctx context.Context, targetUserId, requestUserId id.UUID, newPhone string) (requestId string, err error)
	CompleteBindPhone(ctx context.Context, targetUserId, requestUserId id.UUID, newPhone, verifyCode, requestId string, version int) (v int, err error)
	StartChangeEmail(ctx context.Context, targetUserId, requestUserId id.UUID) (requestId string, err error)
	VerifyNewEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, newEmail, RequestId string) (requestId string, err error)
	CompleteChangeEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error)
	StartChangePhone(ctx context.Context, targetUserId, requestUserId id.UUID) (requestId string, err error)
	VerifyNewPhone(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, newPhone, RequestId string) (requestId string, err error)
	CompleteChangePhone(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error)
	UpdateUserInfo(ctx context.Context, targetUserId, requestUserId id.UUID, nickName, avatar string, gender uint64, version int) (v int, err error, requestId string)
	GetVersion(ctx context.Context, userId id.UUID) (v int, err error)
	AddVersion(ctx context.Context, userId id.UUID) (err error)
	StartDeactivateUser(ctx context.Context, targetUserId, requestUserId id.UUID, queryType QueryType) (requestId string, err error)
	DeactivateUser(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error)
	StartReactiveUser(ctx context.Context, requestUserId id.UUID, phone, email, username string) (allow bool, targetUserId string, requestId string, err error)
	ReactiveUser(ctx context.Context, targetUserId, requestUserId id.UUID, version int, requestId string) (v int, err error)
	StartDeleteUser(ctx context.Context, targetUserId, requestUserId id.UUID, queryType QueryType) (requestId string, err error)
	DeleteUser(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string) (err error, RequestId string)
}

type ServiceImpl struct {
	userRepo repo.UserRepository
	Rds      *redis.Client
	keys     *urds.UserKeys
}

func NewService(database *gorm.DB, rds *redis.Client, env string) UserService {
	return &ServiceImpl{
		userRepo: repo.NewUserRepository(database),
		Rds:      rds,
		keys:     urds.NewUserKeys(env),
	}
}

func (s *ServiceImpl) GetRedis() *redis.Client {
	return s.Rds
}

func (s *ServiceImpl) Register(ctx context.Context, u *models.User, uLogin *models.UserLogin) (error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return err, ""
	}

	if u == nil || uLogin == nil || u.UserName == "" {
		return cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil), requestId
	}

	//查重用户名
	ok, err, t := s.userRepo.ExistDuplicateUser(ctx, u.UserName, u.Email, u.Phone)
	if err != nil {
		return ParseRepoErrorToCommonError(err, "查询用户失败"), ""
	}
	if ok {
		switch t {
		case 1:
			return cerrors.NewCommonError(http.StatusBadRequest, "用户名重复", requestId, nil), requestId
		case 2:
			return cerrors.NewCommonError(http.StatusBadRequest, "邮箱重复", requestId, nil), requestId
		default:
			return cerrors.NewCommonError(http.StatusBadRequest, "电话号码重复", requestId, nil), requestId
		}

	}

	u.ID = id.NewUUID()
	uLogin.UserID = u.ID

	uLogin.Password = Encryption(uLogin.Password)

	if err := s.userRepo.CreateUser(ctx, u, uLogin); err != nil {
		return ParseRepoErrorToCommonError(err, "注册用户失败"), requestId
	}

	// 为新注册用户分配普通用户角色
	_, err = authClient.AssignRoleToUser(ctx, &auth.AssignRoleToUserReq{
		TargetUserId:  u.ID.MarshalBase64(),
		RoleCode:      "user",
		RequestUserId: id.SystemUUID.MarshalBase64(),
	})
	if err != nil {
		logs.ErrorLogger.Error("为新注册用户分配默认角色失败:", zap.Error(err))
	}

	return nil, requestId
}

func (s *ServiceImpl) EmailLogin(ctx context.Context, email, pwd string) (*models.User, *models.Token, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)
	if err != nil {
		return nil, nil, err, ""
	}

	usr, err := s.userRepo.GetUserByEmail(ctx, email)

	return s.LoginWithResp(ctx, usr, pwd, err, true, requestId)
}

func (s *ServiceImpl) PhoneLogin(ctx context.Context, phone, pwd string) (*models.User, *models.Token, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return nil, nil, err, ""
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	return s.LoginWithResp(ctx, usr, pwd, err, true, requestId)
}

func (s *ServiceImpl) UserNameLogin(ctx context.Context, username, pwd string) (*models.User, *models.Token, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return nil, nil, err, ""
	}

	usr, err := s.userRepo.GetUserByUsername(ctx, username)

	return s.LoginWithResp(ctx, usr, pwd, err, true, requestId)
}

func (s *ServiceImpl) SmsSendCode(ctx context.Context, phone string) (string, error) {

	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)

	if err != nil {
		return "", err
	}

	if err := s.Rds.Set(
		ctx,
		s.keys.SmsLoginKey(phone),
		true,
		10*time.Minute,
	).Err(); err != nil {
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", "", err)
	}

	SmsCodeToken := s.keys.SmsVCodeKey(phone)

	if err := s.SendPhoneCode(ctx, SmsCodeToken, phone); err != nil {
		return "", err
	}

	return requestId, nil
}

func (s *ServiceImpl) SmsLogin(ctx context.Context, phone, code, requestId string) (*models.User, *models.Token, error) {

	//校验requestId
	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return nil, nil, err
	}

	//校验验证码
	res, err := s.Rds.Get(ctx, s.keys.SmsVCodeKey(phone)).Result()

	if err != nil {
		return nil, nil, ParseRedisErr(err, requestId)
	}

	if res != code {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	usr, err := s.userRepo.GetUserByPhone(ctx, phone)

	resp, token, err, _ := s.LoginWithResp(ctx, usr, "", err, false, requestId)

	//登录成功,删除凭证
	if err == nil {
		pipeline := s.Rds.Pipeline()

		pipeline.Del(ctx, s.keys.SmsVCodeKey(phone))

		pipeline.Del(ctx, s.keys.SmsLoginKey(phone))

		if _, err = pipeline.Exec(ctx); err != nil {
			return nil, nil, cerrors.NewCommonError(http.StatusInternalServerError, "服务器异常", requestId, nil)
		}
	}

	return resp, token, err
}

func (s *ServiceImpl) GenerateQrCode(ctx context.Context, ip, userAgent string) (string, string, uint64, error) {
	session := qr.NewQRLoginSession(ip, userAgent, 5*time.Minute)
	_, qrCode, err := session.GenerateQR(50, "H")
	if err != nil {
		return "", "", 0, cerrors.NewCommonError(http.StatusInternalServerError, "生成二维码错误", "", err)
	}

	if err = s.Rds.Set(ctx,
		s.keys.QrLoginKey(session.UniqueSig),
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
) (bool, id.UUID, error) {

	//校验链路是否合法
	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return false, id.NewUUID(), err
	}

	//获取uid
	takeUidToken := s.keys.QrStoreUidKey(ticket)

	expireTime := time.Now().Add(time.Duration(timeout) * time.Second).Unix()

	if timeout < 10 || timeout > 600 {
		expireTime = time.Now().Add(time.Duration(30) * time.Second).Unix()
	}

	uid := id.NewUUID()

	isOk := false

	for time.Now().Unix() <= expireTime {
		result, err := s.Rds.Get(ctx, takeUidToken).Result()

		if err != nil && !errors.Is(err, redis.Nil) {
			return false, id.NewUUID(), cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
		}

		uid, err = id.FromString(result)

		if err == nil {
			isOk = true
			break
		}

		time.Sleep(time.Second)
	}

	if !isOk {
		return false, id.NewUUID(), cerrors.NewCommonError(http.StatusNotAcceptable, "请求超时", requestId, nil)
	}

	return true, uid, nil
}

func (s *ServiceImpl) QrCodeLoginStatus(
	ctx context.Context,
	ticket string,
	timeout uint64,
	requestId string,
	uid id.UUID,
) (uint64, *models.User, *models.Token, error) {

	//校验链路是否合法
	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return 6, nil, nil, err
	}
	//校验ticket
	ticketToken := s.keys.QrLoginKey(ticket)

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

	usr, token, err, requestId := s.LoginWithResp(ctx, usr, "", err, false, requestId)

	if err != nil {
		return 6, nil, nil, err
	}

	return status, usr, token, nil
}

func (s *ServiceImpl) QrPreLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) error {

	//校验链路是否合法
	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return err
	}

	//校验二维码是否过期
	ticketToken := s.keys.QrLoginKey(ticket)

	result, err := s.Rds.Get(ctx, ticketToken).Result()

	if err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if result != "1" || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "二维码过期", requestId, err)
	}

	//原子操作
	pipe := s.Rds.Pipeline()

	//续期ticketToken
	pipe.Expire(ctx, ticketToken, 5*time.Minute)

	//写入通过ticket获取uid
	takeUidToken := s.keys.QrStoreUidKey(ticket)

	pipe.Set(ctx, takeUidToken, uid.String(), 5*time.Minute)

	if _, err = pipe.Exec(ctx); err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	}

	return nil
}

func (s *ServiceImpl) ConfirmQrLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) error {
	return s.ConfirmOrCancelQrLogin(ctx, ticket, uid, requestId, 3)
}

func (s *ServiceImpl) CancelQrLogin(ctx context.Context, ticket string, uid id.UUID, requestId string) error {
	return s.ConfirmOrCancelQrLogin(ctx, ticket, uid, requestId, 5)
}

func (s *ServiceImpl) Logout(ctx context.Context, reqeustUid, targetUid id.UUID, token *models.Token) (error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return err, ""
	}

	//权限校验

	//业务代码
	if token == nil {
		return cerrors.NewCommonError(http.StatusBadRequest, "请求错误", "", nil), requestId
	}

	pipe := s.Rds.Pipeline()

	pipe.Set(ctx, s.keys.CommonKeys.BlackRefreshTokenKey(token.RefreshToken), true, 7*24*time.Hour)

	pipe.Set(ctx, s.keys.CommonKeys.BlackAccessTokenKey(token.AccessToken), true, 7*24*time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "redis错误", "", err), requestId
	}

	return nil, requestId
}

func (s *ServiceImpl) GetUserInfoById(ctx context.Context, targetUserId, requestUserId id.UUID) (*models.User, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return nil, err, ""
	}

	if targetUserId.IsZero() || requestUserId.IsZero() {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil), requestId
	}

	wrapper := serializer2.NewSerializerWrapper(serializer2.JSON)

	simple := urds.SimpleCacheComponent[*models.User]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       s.keys.DetailUserInfoKey(targetUserId),
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
		return nil, ParseRepoErrorToCommonError(err, "未知异常"), requestId
	}

	if usr == nil {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "用户不存在或者已经删除", "", nil), requestId
	}

	return &models.User{
		ID:       usr.ID,
		NickName: usr.NickName,
		UserName: usr.UserName,
		Email:    usr.Email,
		Phone:    usr.Phone,
		Gender:   usr.Gender,
		Avatar:   usr.Avatar,
	}, nil, requestId

}

func (s *ServiceImpl) GetUserInfoBySpecialSig(ctx context.Context, sign string, requestUserId id.UUID, queryType QueryType, serialType serializer2.SerializerType) (*models.User, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return nil, err, ""
	}

	if sign == "" || requestUserId.IsZero() {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil), requestId
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
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "参数错误", "", nil), requestId
	}

	wrapper := serializer2.NewSerializerWrapper(serialType)

	simple := urds.SimpleCacheComponent[*models.User]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       s.keys.DetailUserInfoSignKey(suffix, sign),
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
		return nil, ParseRepoErrorToCommonError(err, "未知异常"), requestId
	}

	if usr == nil {
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "用户不存在或者已经删除", "", nil), requestId
	}

	return &models.User{
		ID:       usr.ID,
		NickName: usr.NickName,
		UserName: usr.UserName,
		Email:    usr.Email,
		Phone:    usr.Phone,
		Gender:   usr.Gender,
		Avatar:   usr.Avatar,
	}, nil, requestId

}

func (s *ServiceImpl) ChangePassword(ctx context.Context, targetUserId, requestUserId id.UUID, oldPwd, newPwd string) (error, string) {

	requestId, err := s.GenerateRequestId(ctx, 1*time.Second)

	if err != nil {
		return err, ""
	}

	ok, err := s.userRepo.ComparePassword(ctx, targetUserId, Encryption(oldPwd))

	if err != nil {
		return ParseRepoErrorToCommonError(err, "修改失败"), requestId
	}

	if !ok {
		return cerrors.NewCommonError(http.StatusBadRequest, "旧密码错误", "", nil), requestId
	}

	if err := s.userRepo.UpdatePassword(ctx, targetUserId, Encryption(newPwd)); err != nil {
		return ParseRepoErrorToCommonError(err, "修改失败"), requestId
	}

	return nil, requestId
}

func (s *ServiceImpl) ForgetPassword(ctx context.Context, sign string, queryType QueryType, serialType serializer2.SerializerType, msgType uint64) (id.UUID, string, error) {

	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)

	if err != nil {
		return id.NewUUID(), "", err
	}

	usr, err, _ := s.GetUserInfoBySpecialSig(ctx, sign, id.SystemUUID, queryType, serialType)
	if err != nil {
		return id.NewUUID(), "", err
	}

	ForgetToken := s.keys.ForgetPwdKey(usr.ID)

	var Err error

	switch msgType {
	case 1:
		Err = s.SendEmailCode(ctx, ForgetToken, sign)
	default:
		Err = s.SendPhoneCode(ctx, ForgetToken, sign)
	}
	if Err != nil {
		return id.NewUUID(), "", Err
	}

	return usr.ID, requestId, nil
}

func (s *ServiceImpl) ResetPassword(ctx context.Context, targetUserId, requestUserId id.UUID, newPwd, requestId, VerifyCode string) error {

	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return err
	}

	ForgetToken := s.keys.ForgetPwdKey(targetUserId)

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

	if phone == "" {
		return cerrors.NewCommonError(http.StatusForbidden, "用户未绑定手机号,请绑定", "", nil)
	}

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

	if email == "" {
		return cerrors.NewCommonError(http.StatusForbidden, "用户未绑定邮箱,请绑定", "", nil)
	}

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

func (s *ServiceImpl) StartBindEmail(ctx context.Context, targetUserId, requestUserId id.UUID, newEmail string) (string, error) {
	return s.StartBindPhoneOrEmail(ctx, targetUserId, requestUserId, newEmail, EMAIL)
}

func (s *ServiceImpl) CompleteBindEmail(ctx context.Context, targetUserId, requestUserId id.UUID, newEmail, verifyCode, requestId string, version int) (int, error) {
	return s.CompleteBindPhoneOrEmail(ctx, targetUserId, requestUserId, newEmail, verifyCode, requestId, version, EMAIL)
}

func (s *ServiceImpl) StartBindPhone(ctx context.Context, targetUserId, requestUserId id.UUID, newPhone string) (string, error) {
	return s.StartBindPhoneOrEmail(ctx, targetUserId, requestUserId, newPhone, PHONE)
}

func (s *ServiceImpl) CompleteBindPhone(ctx context.Context, targetUserId, requestUserId id.UUID, newPhone, verifyCode, requestId string, version int) (int, error) {
	return s.CompleteBindPhoneOrEmail(ctx, targetUserId, requestUserId, newPhone, verifyCode, requestId, version, PHONE)
}

func (s *ServiceImpl) StartChangeEmail(ctx context.Context, targetUserId, requestUserId id.UUID) (string, error) {
	return s.StartChangePhoneOrEmail(ctx, targetUserId, requestUserId, EMAIL)
}

func (s *ServiceImpl) VerifyNewEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, newEmail, requestId string) (string, error) {
	return s.VerifyNewPhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, newEmail, requestId, EMAIL)
}

func (s *ServiceImpl) CompleteChangeEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error) {
	return s.CompleteChangePhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, requestId, version, EMAIL)
}

func (s *ServiceImpl) StartChangePhone(ctx context.Context, targetUserId, requestUserId id.UUID) (string, error) {
	return s.StartChangePhoneOrEmail(ctx, targetUserId, requestUserId, PHONE)
}

func (s *ServiceImpl) VerifyNewPhone(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, newPhone, requestId string) (string, error) {
	return s.VerifyNewPhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, newPhone, requestId, PHONE)
}

func (s *ServiceImpl) CompleteChangePhone(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error) {
	return s.CompleteChangePhoneOrEmail(ctx, targetUserId, requestUserId, verifyCode, requestId, version, PHONE)
}

func (s *ServiceImpl) UpdateUserInfo(ctx context.Context, targetUserId, requestUserId id.UUID, nickName, avatar string, gender uint64, version int) (int, error, string) {

	requestId, err := s.GenerateRequestId(ctx, 10*time.Second)

	if err != nil {
		return version, err, ""
	}

	usr := &models.User{
		ID:       targetUserId,
		NickName: nickName,
		Avatar:   avatar,
		Gender:   gender,
		AuditFields: models.AuditFields{
			Version: version,
		},
	}

	err = s.userRepo.UpdateUser(ctx, usr, requestUserId)

	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器错误"), requestId
	}

	s.CleanCache(ctx, usr)

	return version, nil, requestId
}

func (s *ServiceImpl) GetVersion(ctx context.Context, userId id.UUID) (v int, err error) {
	usr, err := s.userRepo.GetUserByID(ctx, userId)
	if err != nil {
		return 0, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	s.Rds.Set(ctx, s.keys.VersionKey(userId), usr.Version, 7*time.Hour)

	return usr.Version, nil
}

func (s *ServiceImpl) AddVersion(ctx context.Context, userId id.UUID) (err error) {
	if err = s.userRepo.AddVersion(ctx, userId); err != nil {
		return ParseRepoErrorToCommonError(err, "服务器异常")
	}
	defer s.Rds.Del(ctx, s.keys.VersionKey(userId))
	return nil
}

func (s *ServiceImpl) StartDeactivateUser(ctx context.Context, targetUserId, requestUserId id.UUID, queryType QueryType) (requestId string, err error) {

	requestId, err = s.GenerateRequestId(ctx, 10*time.Minute)
	if err != nil {
		return "", err
	}

	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)

	if err != nil {
		return "", err
	}

	switch queryType {
	case PHONE:
		if err = s.SendPhoneCode(ctx, s.keys.DeactivateKey(targetUserId), usr.Phone); err != nil {
			return "", err
		}
	case EMAIL:
		if err = s.SendEmailCode(ctx, s.keys.DeactivateKey(targetUserId), usr.Email); err != nil {
			return "", err
		}
	default:
		return "", cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) DeactivateUser(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int) (v int, err error) {

	if err = s.VerifyRequestID(ctx, requestId); err != nil {
		return version, err
	}

	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)
	if err != nil {
		return version, err
	}

	vCode, err := s.Rds.Get(ctx, s.keys.DeactivateKey(targetUserId)).Result()

	if err != nil {
		return version, ParseRedisErr(err, requestId)
	}

	//校验验证码
	if verifyCode != vCode {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil)
	}

	v, err = s.userRepo.FreezeUser(ctx, targetUserId, version, requestUserId)

	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	s.CleanCache(ctx, usr)

	return v, nil
}

func (s *ServiceImpl) StartReactiveUser(ctx context.Context, requestUserId id.UUID, phone, email, username string) (allow bool, targetUserId string, requestId string, err error) {
	requestId, err = s.GenerateRequestId(ctx, 10*time.Minute)

	if err != nil {
		return false, "", "", err
	}

	usr, err := s.userRepo.GetUserByUsername(ctx, username)

	if usr == nil {
		return false, "", "", cerrors.NewCommonError(http.StatusBadRequest, "用户名错误", "", nil)
	}

	if err != nil {
		return false, "", "", ParseRepoErrorToCommonError(err, "服务器异常")
	}

	if usr.Phone == phone && usr.Email == email {
		return true, usr.ID.MarshalBase64(), requestId, nil
	}

	return false, "", requestId, nil
}

func (s *ServiceImpl) ReactiveUser(ctx context.Context, targetUserId, requestUserId id.UUID, version int, requestId string) (v int, err error) {

	if err = s.VerifyRequestID(ctx, requestId); err != nil {
		return version, err
	}

	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)
	if err != nil {
		return version, err
	}

	v, err = s.userRepo.UnfreezeUser(ctx, targetUserId, version, requestUserId)
	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	s.CleanCache(ctx, usr)

	return v, nil
}

func (s *ServiceImpl) StartDeleteUser(ctx context.Context, targetUserId, requestUserId id.UUID, queryType QueryType) (requestId string, err error) {
	requestId, err = s.GenerateRequestId(ctx, 1*time.Second)
	if err != nil {
		return "", err
	}

	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)

	if err != nil {
		return requestId, err
	}

	switch queryType {
	case PHONE:
		if err := s.SendPhoneCode(ctx, s.keys.DeleteKey(targetUserId), usr.Phone); err != nil {
			return requestId, err
		}
	case EMAIL:
		if err := s.SendEmailCode(ctx, s.keys.DeleteKey(targetUserId), usr.Email); err != nil {
			return requestId, err
		}
	default:
		return requestId, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", requestId, nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) DeleteUser(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string) (err error, RequestId string) {
	if err = s.VerifyRequestID(ctx, requestId); err != nil {
		return err, requestId
	}

	vCode, err := s.Rds.Get(ctx, s.keys.DeleteKey(targetUserId)).Result()

	if err != nil {
		return ParseRedisErr(err, requestId), requestId
	}

	if verifyCode != vCode {
		return cerrors.NewCommonError(http.StatusBadRequest, "验证码错误", requestId, nil), requestId
	}

	if err = s.userRepo.DeleteUser(ctx, targetUserId, requestUserId); err != nil {
		return ParseRepoErrorToCommonError(err, "服务器异常"), requestId
	}

	return nil, requestId
}

func (s *ServiceImpl) ConfirmOrCancelQrLogin(
	ctx context.Context,
	ticket string,
	uid id.UUID,
	requestId string,
	status int,
) error {
	//校验链路是否合法
	if err := s.VerifyRequestID(ctx, requestId); err != nil {
		return err
	}

	//校验上下文用户是否为同一个人
	takeUidToken := s.keys.QrStoreUidKey(ticket)

	result, err := s.Rds.Get(ctx, takeUidToken).Result()

	if err != nil && !errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	} else if result != uid.String() || errors.Is(err, redis.Nil) {
		return cerrors.NewCommonError(http.StatusBadRequest, "用户错误,不允许的操作", requestId, err)
	}

	//重置ticket状态
	ticketToken := s.keys.QrLoginKey(ticket)

	if err = s.Rds.Set(ctx, ticketToken, status, 5*time.Minute).Err(); err != nil {
		return cerrors.NewCommonError(http.StatusInternalServerError, "Redis错误", requestId, err)
	}

	return nil
}

func (s *ServiceImpl) StartBindPhoneOrEmail(ctx context.Context, targetUserId, requestUserId id.UUID, sign string, form QueryType) (string, error) {
	requestId, err := s.GenerateRequestId(ctx, 10*time.Minute)
	if err != nil {
		return "", err
	}

	switch form {
	case PHONE:
		phoneToken := s.keys.BindPhoneKey(sign, targetUserId)
		if err = s.SendPhoneCode(ctx, phoneToken, sign); err != nil {
			return "", err
		}
	case EMAIL:
		emailToken := s.keys.BindEmailKey(sign, targetUserId)
		if err = s.SendEmailCode(ctx, emailToken, sign); err != nil {
			return "", err
		}
	default:
		return "", cerrors.NewCommonError(http.StatusBadRequest, "请求类型错误", "", nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) CompleteBindPhoneOrEmail(ctx context.Context, targetUserId, requestUserId id.UUID, sign, verifyCode, requestId string, version int, form QueryType) (v int, err error) {
	//请求用户
	usr, err := s.userRepo.GetUserByID(ctx, targetUserId)
	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	//CAS校验
	if usr.Version != version {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "令牌过期,请使用新令牌", requestId, nil)
	}

	var Token string

	switch form {
	case EMAIL:
		Token = s.keys.BindEmailKey(sign, targetUserId)
	case PHONE:
		Token = s.keys.BindPhoneKey(sign, targetUserId)
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

func (s *ServiceImpl) StartChangePhoneOrEmail(ctx context.Context, targetUserId, requestUserId id.UUID, form QueryType) (requestId string, err error) {

	//生成requestId
	requestId, err = s.GenerateRequestId(ctx, 10*time.Minute)
	if err != nil {
		return "", err
	}

	//获取用户信息
	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)

	if err != nil {
		return "", err
	}

	//发送验证码
	switch form {
	case PHONE:
		if usr.Phone == "" {
			return "", cerrors.NewCommonError(http.StatusForbidden, "请先绑定手机号", "", nil)
		}
		phoneToken := s.keys.ChangePhone1Key(usr.Phone, targetUserId)
		if err := s.SendPhoneCode(ctx, phoneToken, usr.Phone); err != nil {
			return "", err
		}
	case EMAIL:
		if usr.Email == "" {
			return "", cerrors.NewCommonError(http.StatusForbidden, "请先绑定邮箱", "", nil)
		}
		emailToken := s.keys.ChangeEmail1Key(usr.Email, targetUserId)
		if err := s.SendEmailCode(ctx, emailToken, usr.Phone); err != nil {
			return "", err
		}
	default:
		return "", cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	return requestId, nil
}

func (s *ServiceImpl) VerifyNewPhoneOrEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, sign, RequestId string, form QueryType) (requestId string, err error) {
	//校验requestId
	if err = s.VerifyRequestID(ctx, RequestId); err != nil {
		return "", err
	}

	//获取用户信息(因为前面有缓存这次查询可以接受)
	usr, err, _ := s.GetUserInfoById(ctx, targetUserId, requestUserId)
	if err != nil {
		return requestId, err
	}

	//请求验证码
	var Token string

	switch form {
	case PHONE:
		Token = s.keys.ChangePhone1Key(usr.Phone, targetUserId)
	case EMAIL:
		Token = s.keys.ChangeEmail1Key(usr.Email, targetUserId)
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
		newPhoneToken := s.keys.ChangePhone2Key(targetUserId)
		if err := s.SendPhoneCode(ctx, newPhoneToken, sign); err != nil {
			return requestId, err
		}
		storeToken = s.keys.StorePhoneKey(targetUserId)
	case EMAIL:
		newEmailToken := s.keys.ChangeEmail2Key(targetUserId)
		if err := s.SendEmailCode(ctx, newEmailToken, sign); err != nil {
			return requestId, err
		}
		storeToken = s.keys.StoreEmailKey(targetUserId)
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

func (s *ServiceImpl) CompleteChangePhoneOrEmail(ctx context.Context, targetUserId, requestUserId id.UUID, verifyCode, requestId string, version int, form QueryType) (v int, err error) {

	//请求用户
	usr, err := s.userRepo.GetUserByID(ctx, targetUserId)
	if err != nil {
		return version, ParseRepoErrorToCommonError(err, "服务器异常")
	}

	//CAS校验
	if usr.Version != version {
		return version, cerrors.NewCommonError(http.StatusBadRequest, "令牌过期,请使用新令牌", requestId, nil)
	}

	if err = s.VerifyRequestID(ctx, requestId); err != nil {
		return version, err
	}

	var Token string

	switch form {
	case PHONE:
		Token = s.keys.ChangePhone2Key(targetUserId)
	case EMAIL:
		Token = s.keys.ChangeEmail2Key(targetUserId)
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
		storeToken = s.keys.StorePhoneKey(targetUserId)
	case EMAIL:
		storeToken = s.keys.StoreEmailKey(targetUserId)
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
) (*models.User, *models.Token, error, string) {

	//错误处理部分
	if err != nil {
		return nil, nil, ParseRepoErrorToCommonError(err, "用户登录失败"), requestId
	}

	if usr == nil {
		return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "获取用户失败", requestId, nil), requestId
	}

	if hasPwd {
		//校验密码部分
		ok, err := s.userRepo.ComparePassword(ctx, usr.ID, Encryption(pwd))
		if err != nil {
			//错误处理部分
			return nil, nil, ParseRepoErrorToCommonError(err, "用户登录失败"), requestId
		}

		if !ok {
			return nil, nil, cerrors.NewCommonError(http.StatusBadRequest, "用户名或者密码错误", requestId, nil), requestId
		}
	}

	if usr.Status == 1 {
		return nil, nil, cerrors.NewCommonError(http.StatusNotAcceptable, "用户已被冻结", requestId, nil), requestId
	}

	//获取token部分
	resp, err := s.RequestToken(ctx, usr.ID, usr.Version)

	if err != nil {
		return nil, nil, err, requestId
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
	}, nil, requestId

}

// RequestToken 辅助函数(用于请求token)
func (s *ServiceImpl) RequestToken(ctx context.Context, userId id.UUID, version int) (*auth.IssueTokenResp, error) {

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
	return urds.GenerateRequestId(s.Rds, s.keys, ctx, expire)
}

func (s *ServiceImpl) VerifyRequestID(ctx context.Context, requestId string) error {
	return urds.VerityRequestID(s.Rds, s.keys, ctx, requestId, 20*time.Minute)
}

func (s *ServiceImpl) CleanCache(ctx context.Context, usr *models.User) {

	pipe := s.Rds.Pipeline()

	pipe.Del(ctx, s.keys.DetailUserInfoKey(usr.ID))
	pipe.Del(ctx, s.keys.DetailUserInfoSignKey("username", usr.UserName))
	pipe.Del(ctx, s.keys.DetailUserInfoSignKey("email", usr.Email))
	pipe.Del(ctx, s.keys.DetailUserInfoSignKey("phone", usr.Phone))

	pipe.Exec(ctx)
}
