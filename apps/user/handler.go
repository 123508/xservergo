package main

import (
	"context"
	"net/http"
	"time"

	"github.com/123508/xservergo/pkg/util/component/serializer"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/123508/xservergo/pkg/util/validate"

	"github.com/123508/xservergo/apps/user/service"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/123508/xservergo/kitex_gen/user"
)

func parseServiceErrToHandlerError(ctx context.Context, err error, requestId string, version uint64) (*user.OperationResult, error) {

	var code uint64
	var message string
	if com, ok := err.(*cerrors.CommonError); ok {
		err = cerrors.NewGRPCError(com.Code, com.Message)
		code = com.Code
		message = com.Message
	} else {
		code = http.StatusInternalServerError
		message = "服务器异常,操作失败"
	}

	resp := &user.OperationResult{
		Success:   false,
		Code:      code,
		Message:   message,
		Timestamp: time.Now().String(),
		Version:   0,
	}

	if requestId != "" {
		resp.RequestId = requestId
	}

	if version > 0 {
		resp.Version = version
	}

	return resp, cerrors.NewGRPCError(code, message)
}

func unmarshalUID(ctx context.Context, uid string, version uint64) (*user.OperationResult, error, id.UUID) {

	if uid == "" || len(uid) == 0 {
		return nil, nil, id.SystemUUID
	}

	Uid := id.NewUUID()
	if err := Uid.UnmarshalBase64(uid); err != nil {

		resp := &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}

		if version > 0 {
			resp.Version = version
		}

		return resp, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误"), Uid
	}

	return nil, nil, Uid
}

func marshalUID(ctx context.Context, uid id.UUID) string {
	return uid.MarshalBase64()
}

// UserServiceImpl implements the last service interface defined in the IDL.
type UserServiceImpl struct {
	userService service.UserService
}

func NewUserServiceImpl(database *gorm.DB, rds *redis.Client, env string) *UserServiceImpl {
	return &UserServiceImpl{
		userService: service.NewService(database, rds, env),
	}
}

// Register implements the UserServiceImpl interface.
func (s *UserServiceImpl) Register(ctx context.Context, req *user.RegisterReq) (resp *user.OperationResult, err error) {

	if !validate.IsValidateUsername(req.Username) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "username错误,只允许字母、数字和下划线",
			Timestamp: time.Now().String(),
			Version:   0,
		}, nil
	}

	if !validate.IsValidateGender(req.Gender) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "性别错误,非法请求",
			Timestamp: time.Now().String(),
			Version:   0,
		}, nil
	}

	//校验手机号(手机号可以被跳过)

	if req.Phone != "" {
		if ok, _, _ := validate.IsValidateE164Phone(req.Phone); !ok {
			return &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "手机号错误,请重新输入",
				Timestamp: time.Now().String(),
				Version:   0,
			}, nil
		}
	}

	//校验邮箱(邮箱可以被跳过)
	if req.Email != "" && !validate.IsValidateEmail(req.Email) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "邮箱错误,请重新输入",
			Timestamp: time.Now().String(),
			Version:   0,
		}, nil
	}

	timeNow := time.Now()
	version := 1
	u := &models.User{
		NickName: req.Nickname,
		UserName: req.Username,
		Email:    req.Email,
		Phone:    req.Phone,
		Gender:   req.Gender,
		Status:   0,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			Version:   &version,
		},
	}

	uLogin := &models.UserLogin{
		Password: req.Password,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			Version:   &version,
		},
	}

	err, requestId := s.userService.Register(ctx, u, uLogin)
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "创建用户成功",
		Timestamp: time.Now().String(),
		RequestId: requestId,
		Version:   0,
	}, err
}

// EmailLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) EmailLogin(ctx context.Context, req *user.EmailLoginReq) (resp *user.LoginResp, err error) {

	if req.Email == "" || req.Password == "" {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名或者密码不能为空")
	}

	if !validate.IsValidateEmail(req.Email) {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
	}

	login, token, err, requestId := s.userService.EmailLogin(ctx, req.Email, req.Password)

	resp = &user.LoginResp{}

	if err != nil {
		_, err := parseServiceErrToHandlerError(ctx, err, requestId, 0)
		return &user.LoginResp{}, err
	}

	return &user.LoginResp{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		UserInfo: &user.UserInfo{
			UserId:   marshalUID(ctx, login.ID),
			Username: login.UserName,
			Nickname: login.NickName,
			Avatar:   login.Avatar,
		},
	}, err
}

// PhoneLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) PhoneLogin(ctx context.Context, req *user.PhoneLoginReq) (resp *user.LoginResp, err error) {

	if req.Phone == "" || req.Password == "" {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名或者密码不能为空")
	}

	if ok, _, _ := validate.IsValidateE164Phone(req.Phone); !ok {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
	}

	login, token, err, _ := s.userService.PhoneLogin(ctx, req.Phone, req.Password)

	resp = &user.LoginResp{}

	if err != nil {

		com, ok := err.(*cerrors.CommonError)

		if ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "用户登录失败")
		}

	} else {

		resp.AccessToken = token.AccessToken
		resp.RefreshToken = token.RefreshToken
		resp.UserInfo = &user.UserInfo{
			UserId:   marshalUID(ctx, login.ID),
			Username: login.UserName,
			Nickname: login.NickName,
			Avatar:   login.Avatar,
		}
	}

	return resp, err
}

// AccountLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) AccountLogin(ctx context.Context, req *user.AccountLoginReq) (resp *user.LoginResp, err error) {

	if req.Username == "" || req.Password == "" {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名或者密码不能为空")
	}

	if !validate.IsValidateUsername(req.Username) {
		return &user.LoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名格式错误")
	}

	login, token, err, _ := s.userService.UserNameLogin(ctx, req.Username, req.Password)

	if err != nil {

		com, ok := err.(*cerrors.CommonError)

		if ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "用户登录失败")
		}

		return &user.LoginResp{}, err
	}

	return &user.LoginResp{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		UserInfo: &user.UserInfo{
			UserId:   marshalUID(ctx, login.ID),
			Username: login.UserName,
			Nickname: login.NickName,
			Avatar:   login.Avatar,
		},
	}, nil
}

// SmsLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) SmsLogin(ctx context.Context, req *user.SmsLoginReq) (resp *user.SmsLoginResp, err error) {

	if ok, _, _ := validate.IsValidateE164Phone(req.Phone); !ok {
		return &user.SmsLoginResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
	}

	if req.Flow == 0 {
		requestId, err := s.userService.SmsSendCode(ctx, req.Phone)
		if err != nil {
			return &user.SmsLoginResp{}, cerrors.NewGRPCError(http.StatusInternalServerError, "发送验证码错误")
		} else {
			return &user.SmsLoginResp{
				Result: &user.SmsLoginResp_CodeSent{
					CodeSent: &user.CodeSentInfo{
						RequestId:  requestId,
						ExpireTime: uint64((10 * time.Minute).Milliseconds()),
					},
				},
			}, nil
		}
	} else {

		login, token, err := s.userService.SmsLogin(ctx, req.Phone, req.Code, req.RequestId)
		if err != nil {
			if com, ok := err.(*cerrors.CommonError); ok {
				return &user.SmsLoginResp{}, cerrors.NewGRPCError(com.Code, com.Message)
			} else {
				return &user.SmsLoginResp{}, cerrors.NewGRPCError(http.StatusInternalServerError, "登录失败")
			}
		}

		return &user.SmsLoginResp{
			Result: &user.SmsLoginResp_Login{
				Login: &user.LoginResp{
					RefreshToken: token.RefreshToken,
					AccessToken:  token.AccessToken,
					UserInfo: &user.UserInfo{
						UserId:   marshalUID(ctx, login.ID),
						Username: login.UserName,
						Nickname: login.NickName,
						Avatar:   login.Avatar,
					},
				}},
		}, nil
	}
}

// GenerateQrCode implements the UserServiceImpl interface.
func (s *UserServiceImpl) GenerateQrCode(ctx context.Context, req *user.GenerateQrCodeReq) (resp *user.GenerateQrCodeResp, err error) {
	qrCode, requestId, expiresAt, err := s.userService.GenerateQrCode(ctx, req.ClientIp, req.UserAgent)

	resp = &user.GenerateQrCodeResp{}

	if err != nil {

		com, ok := err.(*cerrors.CommonError)

		if ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "用户登录失败")
		}
	} else {
		resp.QrCodeUrl = qrCode
		resp.ExpiresAt = expiresAt
		resp.RequestId = requestId
	}
	return resp, err
}

// QrCodePreLoginStatus implements the UserServiceImpl interface.
func (s *UserServiceImpl) QrCodePreLoginStatus(ctx context.Context, req *user.QrCodePreLoginStatusReq) (resp *user.QrCodePreLoginStatusResp, err error) {
	status, uid, err := s.userService.QrCodePreLoginStatus(ctx, req.Ticket, req.Timeout, req.RequestId)

	resp = &user.QrCodePreLoginStatusResp{}

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		}
		err = cerrors.NewGRPCError(http.StatusInternalServerError, "预登录失败")
		resp.Ok = false
	} else {
		if status {
			resp.Ok = status
			resp.UserId = marshalUID(ctx, uid)
		} else {
			resp.Ok = false
		}
	}
	return resp, err
}

// QrCodeLoginStatus implements the UserServiceImpl interface.
func (s *UserServiceImpl) QrCodeLoginStatus(ctx context.Context, req *user.QrCodeLoginStatusReq) (resp *user.QrCodeLoginStatusResp, err error) {

	_, err, uid := unmarshalUID(ctx, req.UserId, 0)
	if err != nil {
		return &user.QrCodeLoginStatusResp{
			Status: 6,
			LoginResp: &user.LoginResponse{
				Result: &user.LoginResponse_Failure{
					Failure: &user.LoginFailure{
						Code:    http.StatusBadRequest,
						Message: "请求参数错误",
					},
				},
			},
			NextPollIn: req.Timeout,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	status, usr, token, err := s.userService.QrCodeLoginStatus(ctx, req.Ticket, req.Timeout, req.RequestId, uid)

	resp = &user.QrCodeLoginStatusResp{
		Status:     user.QrCodeLoginStatusResp_Status(status),
		NextPollIn: req.Timeout,
	}

	if err != nil {

		var code uint64
		var message string

		if com, ok := err.(*cerrors.CommonError); ok {
			code = com.Code
			message = com.Message
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			code = http.StatusInternalServerError
			message = "服务器出错"
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "服务器出错")
		}

		resp.LoginResp = &user.LoginResponse{
			Result: &user.LoginResponse_Failure{
				Failure: &user.LoginFailure{
					Code:    code,
					Message: message,
				},
			},
		}
	} else {

		resp.NextPollIn = 0

		if status == 3 {
			resp.LoginResp = &user.LoginResponse{
				Result: &user.LoginResponse_Success{
					Success: &user.LoginResp{
						AccessToken:  token.AccessToken,
						RefreshToken: token.RefreshToken,
						UserInfo: &user.UserInfo{
							UserId:   req.UserId,
							Username: usr.UserName,
							Nickname: usr.NickName,
							Avatar:   usr.Avatar,
						},
					},
				},
			}
		}
	}

	return resp, err
}

// QrPreLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) QrPreLogin(ctx context.Context, req *user.QrPreLoginReq) (resp *user.QrPreLoginResp, err error) {

	_, err, uid := unmarshalUID(ctx, req.UserId, 0)

	if err != nil {
		return &user.QrPreLoginResp{
			Ok:        false,
			RequestId: req.RequestId,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	ok, err := s.userService.QrPreLogin(ctx, req.Ticket, uid, req.RequestId)
	resp = &user.QrPreLoginResp{
		Ok:        ok,
		RequestId: req.RequestId,
	}
	if err != nil {

		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusBadRequest, "用户登录失败")
		}
	}

	return resp, err
}

// ConfirmQrLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) ConfirmQrLogin(ctx context.Context, req *user.ConfirmQrLoginReq) (resp *user.Empty, err error) {
	resp = &user.Empty{}

	_, err, uid := unmarshalUID(ctx, req.UserId, 0)
	if err != nil {
		return resp, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	if err = s.userService.ConfirmQrLogin(ctx, req.Ticket, uid, req.RequestId); err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "登录失败,请重试")
		}
		return resp, err
	}
	return resp, nil
}

// CancelQrLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) CancelQrLogin(ctx context.Context, req *user.CancelQrLoginReq) (resp *user.Empty, err error) {
	resp = &user.Empty{}

	_, err, uid := unmarshalUID(ctx, req.UserId, 0)

	if err != nil {
		return resp, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	if err = s.userService.CancelQrLogin(ctx, req.Ticket, uid, req.RequestId); err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "登录失败,请重试")
		}
		return resp, err
	}
	return resp, nil
}

// OAuthLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) OAuthLogin(ctx context.Context, req *user.OAuthLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// Logout implements the UserServiceImpl interface.
func (s *UserServiceImpl) Logout(ctx context.Context, req *user.LogoutReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	err, requestId := s.userService.Logout(ctx, requestUid, targetUid, &models.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
	})

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "成功退出",
		Timestamp: time.Now().String(),
		RequestId: requestId,
		Version:   0,
	}, nil

}

// ChangePassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ChangePassword(ctx context.Context, req *user.ChangePasswordReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	err, requestId := s.userService.ChangePassword(ctx, targetUid, requestUid, req.OldPassword, req.NewPassword)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改密码成功",
		Timestamp: time.Now().String(),
		RequestId: requestId,
		Version:   0,
	}, nil
}

// ForgotPassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ForgotPassword(ctx context.Context, req *user.ForgotPasswordReq) (resp *user.OperationResult, err error) {
	var ok bool
	var uid id.UUID
	var requestId string

	execute := false

	if !execute && req.GetUsername() != "" {
		username := req.GetUsername()

		if !validate.IsValidateUsername(username) {
			return &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "用户名格式错误",
				Timestamp: time.Now().String(),
				Version:   0,
			}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名格式错误")
		}
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, username, service.USERNAME, serializer.JSON, req.Type)
		execute = true
	}

	if !execute && req.GetEmail() != "" {

		email := req.GetEmail()

		if !validate.IsValidateEmail(email) {
			return &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "邮箱格式错误",
				Timestamp: time.Now().String(),
				Version:   0,
			}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
		}
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, email, service.EMAIL, serializer.JSON, req.Type)
		execute = true
	}

	if !execute && req.GetPhone() != "" {

		phone := req.GetPhone()

		if allow, _, _ := validate.IsValidateE164Phone(phone); !allow {
			return &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "手机号格式错误",
				Timestamp: time.Now().String(),
				Version:   0,
			}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
		}
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, phone, service.PHONE, serializer.JSON, req.Type)
		execute = true
	}

	if !execute {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:       ok,
		Code:          http.StatusOK,
		Message:       "成功",
		RequestId:     requestId,
		Timestamp:     time.Now().String(),
		RequestUserId: marshalUID(ctx, uid),
		Version:       0,
	}, nil
}

// ResetPassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ResetPassword(ctx context.Context, req *user.ResetPasswordReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	if err = s.userService.ResetPassword(ctx, targetUid, requestUid, req.NewPassword, req.RequestId, req.VerificationToken); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "", 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "更新成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// StartBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartBindEmail(ctx context.Context, req *user.StartBindEmailReq) (resp *user.OperationResult, err error) {

	if !validate.IsValidateEmail(req.NewEmail) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "邮箱格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
	}

	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartBindEmail(ctx, targetUid, requestUid, req.NewEmail)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// CompleteBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindEmail(ctx context.Context, req *user.CompleteBindEmailReq) (resp *user.OperationResult, err error) {

	if !validate.IsValidateEmail(req.NewEmail) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "邮箱格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
	}

	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)
	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return res, err
	}

	v, err := s.userService.CompleteBindEmail(ctx, targetUid, requestUid, req.NewEmail, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		res, err = parseServiceErrToHandlerError(ctx, err, "", req.Version)
		return res, err
	}
	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "绑定成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   uint64(v),
	}, nil
}

// StartChangeEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartChangeEmail(ctx context.Context, req *user.StartChangeEmailReq) (resp *user.OperationResult, err error) {
	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartChangeEmail(ctx, targetUid, requestUid)
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}
	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送验证码成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// VerifyNewEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) VerifyNewEmail(ctx context.Context, req *user.VerifyNewEmailReq) (resp *user.OperationResult, err error) {

	if !validate.IsValidateEmail(req.NewEmail) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "邮箱格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
	}

	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.VerifyNewEmail(ctx, targetUid, requestUid, req.VerificationCode, req.NewEmail, req.RequestId)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "请求成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// CompleteChangeEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteChangeEmail(ctx context.Context, req *user.CompleteChangeEmailReq) (resp *user.OperationResult, err error) {
	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return resp, err
	}

	v, err := s.userService.CompleteChangeEmail(ctx, targetUid, requestUid, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		resp, err = parseServiceErrToHandlerError(ctx, err, req.RequestId, req.Version)
		return resp, err
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   uint64(v),
	}, nil
}

// StartBindPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartBindPhone(ctx context.Context, req *user.StartBindPhoneReq) (resp *user.OperationResult, err error) {

	if ok, _, _ := validate.IsValidateE164Phone(req.NewPhone); !ok {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "手机号格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
	}

	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartBindPhone(ctx, targetUid, requestUid, req.NewPhone)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// CompleteBindPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindPhone(ctx context.Context, req *user.CompleteBindPhoneReq) (resp *user.OperationResult, err error) {

	if ok, _, _ := validate.IsValidateE164Phone(req.NewPhone); !ok {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "手机号格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
	}

	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return res, err
	}

	v, err := s.userService.CompleteBindPhone(ctx, targetUid, requestUid, req.NewPhone, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		res, err = parseServiceErrToHandlerError(ctx, err, "", req.Version)
		return res, err
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   uint64(v),
	}, nil
}

// StartChangePhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartChangePhone(ctx context.Context, req *user.StartChangePhoneReq) (resp *user.OperationResult, err error) {
	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartChangePhone(ctx, targetUid, requestUid)
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}
	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送验证码成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// VerifyNewPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) VerifyNewPhone(ctx context.Context, req *user.VerifyNewPhoneReq) (resp *user.OperationResult, err error) {

	if ok, _, _ := validate.IsValidateE164Phone(req.NewPhone); !ok {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "手机号格式错误",
			Timestamp: time.Now().String(),
			Version:   0,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
	}

	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.VerifyNewPhone(ctx, targetUid, requestUid, req.VerificationCode, req.NewPhone, req.RequestId)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "请求成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
		Version:   0,
	}, nil
}

// CompleteChangePhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteChangePhone(ctx context.Context, req *user.CompleteChangePhoneReq) (resp *user.OperationResult, err error) {
	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return resp, err
	}

	v, err := s.userService.CompleteChangePhone(ctx, targetUid, requestUid, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		resp, err = parseServiceErrToHandlerError(ctx, err, req.RequestId, req.Version)
		return resp, err
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   uint64(v),
	}, nil
}

// GetUserInfoById implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetUserInfoById(ctx context.Context, req *user.GetUserInfoByIdReq) (resp *user.UserInfoResp, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	userinfo, err, requestId := s.userService.GetUserInfoById(ctx, targetUid, requestUid)

	if err != nil {
		result, err := parseServiceErrToHandlerError(ctx, err, requestId, 0)
		return &user.UserInfoResp{
			Result: result,
		}, err
	}

	if userinfo == nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusForbidden,
				Message:   "用户不存在或已经删除",
				Timestamp: time.Now().String(),
				RequestId: requestId,
				Version:   0,
			},
		}, cerrors.NewGRPCError(http.StatusForbidden, "用户不存在或已经删除")
	}

	return &user.UserInfoResp{
		Result: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "查询成功",
			Timestamp: time.Now().String(),
			RequestId: requestId,
			Version:   0,
		},
		UserInfo: &user.UserInfo{
			UserId:   marshalUID(ctx, userinfo.ID),
			Username: userinfo.UserName,
			Nickname: userinfo.NickName,
			Gender:   userinfo.Gender,
			Avatar:   userinfo.Avatar,
			Phone:    userinfo.Phone,
			Email:    userinfo.Email,
		},
	}, nil
}

// GetUserInfoByOthers implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetUserInfoByOthers(ctx context.Context, req *user.GetUserInfoByOthersReq) (resp *user.UserInfoResp, err error) {

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	var userinfo *models.User

	requestId := ""

	if req.GetUsername() != "" {

		username := req.GetUsername()

		if !validate.IsValidateUsername(username) {
			return &user.UserInfoResp{
				Result: &user.OperationResult{
					Success:   false,
					Code:      http.StatusBadRequest,
					Message:   "用户名格式错误",
					Timestamp: time.Now().String(),
					Version:   0,
				},
			}, cerrors.NewGRPCError(http.StatusBadRequest, "用户名格式错误")
		}

		userinfo, err, requestId = s.userService.GetUserInfoBySpecialSig(ctx, username, requestUid, service.USERNAME, serializer.JSON)
	} else if req.GetEmail() != "" {

		email := req.GetEmail()

		if !validate.IsValidateEmail(email) {
			return &user.UserInfoResp{
				Result: &user.OperationResult{
					Success:   false,
					Code:      http.StatusBadRequest,
					Message:   "邮箱格式错误",
					Timestamp: time.Now().String(),
					Version:   0,
				},
			}, cerrors.NewGRPCError(http.StatusBadRequest, "邮箱格式错误")
		}

		userinfo, err, requestId = s.userService.GetUserInfoBySpecialSig(ctx, req.GetEmail(), requestUid, service.EMAIL, serializer.JSON)
	} else if req.GetPhone() != "" {

		phone := req.GetPhone()

		if ok, _, _ := validate.IsValidateE164Phone(phone); !ok {
			return &user.UserInfoResp{
				Result: &user.OperationResult{
					Success:   false,
					Code:      http.StatusBadRequest,
					Message:   "手机号格式错误",
					Timestamp: time.Now().String(),
					Version:   0,
				},
			}, cerrors.NewGRPCError(http.StatusBadRequest, "手机号格式错误")
		}

		userinfo, err, requestId = s.userService.GetUserInfoBySpecialSig(ctx, phone, requestUid, service.PHONE, serializer.JSON)
	} else {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "参数错误",
				Timestamp: time.Now().String(),
				RequestId: requestId,
				Version:   0,
			},
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}

	if err != nil {
		result, err := parseServiceErrToHandlerError(ctx, err, requestId, 0)
		return &user.UserInfoResp{
			Result: result,
		}, err
	}

	if userinfo == nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusForbidden,
				Message:   "用户不存在或已经删除",
				Timestamp: time.Now().String(),
				RequestId: requestId,
				Version:   0,
			},
		}, cerrors.NewGRPCError(http.StatusForbidden, "用户不存在或已经删除")
	}

	return &user.UserInfoResp{
		Result: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "查询成功",
			Timestamp: time.Now().String(),
			RequestId: requestId,
			Version:   0,
		},
		UserInfo: &user.UserInfo{
			UserId:   marshalUID(ctx, userinfo.ID),
			Username: userinfo.UserName,
			Nickname: userinfo.NickName,
			Gender:   userinfo.Gender,
			Avatar:   userinfo.Avatar,
		},
	}, nil
}

// UpdateUserInfo implements the UserServiceImpl interface.
func (s *UserServiceImpl) UpdateUserInfo(ctx context.Context, req *user.UpdateUserInfoReq) (resp *user.OperationResult, err error) {

	if !validate.IsValidateGender(req.Gender) {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "非法请求,性别错误",
			Timestamp: time.Now().String(),
			Version:   req.Version,
		}, cerrors.NewGRPCError(http.StatusBadRequest, "非法请求")
	}

	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	v, err, requestId := s.userService.UpdateUserInfo(ctx, targetUid, requestUid, req.Nickname, req.Avatar, req.Gender, int(req.Version))

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, uint64(v))
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改成功",
		Timestamp: time.Now().String(),
		RequestId: requestId,
		Version:   uint64(v),
	}, nil
}

// ListUsers implements the UserServiceImpl interface.
func (s *UserServiceImpl) ListUsers(ctx context.Context, req *user.ListUsersReq) (resp *user.ListUsersResp, err error) {
	// TODO: Your code here...
	return
}

// SearchUserByUsername implements the UserServiceImpl interface.
func (s *UserServiceImpl) SearchUserByUsername(ctx context.Context, req *user.SearchUserByUsernameReq) (resp *user.SearchUserByUsernameResp, err error) {
	// TODO: Your code here...
	return
}

// StartDeactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartDeactivateUser(ctx context.Context, req *user.StartDeactivateReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	requestId, err := s.userService.StartDeactivateUser(ctx, targetUid, requestUid, service.QueryType(req.QueryType))

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, "", 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "请求成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
	}, nil
}

// DeactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) DeactivateUser(ctx context.Context, req *user.DeactivateUserReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return res, err
	}

	v, err := s.userService.DeactivateUser(ctx, targetUid, requestUid, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, req.RequestId, uint64(v))
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "请求成功",
		Timestamp: time.Now().String(),
		RequestId: req.RequestId,
		Version:   uint64(v),
	}, nil
}

// StartReactiveUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartReactiveUser(ctx context.Context, req *user.StartReactivateUserReq) (resp *user.StartReactivateUserResp, err error) {
	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return &user.StartReactivateUserResp{
			Op:              res,
			TargetUserId:    "",
			AllowedReactive: false,
		}, err
	}

	allow, targetUserId, requestId, err := s.userService.StartReactiveUser(ctx, requestUid, req.Phone, req.Email, req.Username)
	if err != nil {
		handlerError, err := parseServiceErrToHandlerError(ctx, err, "", 0)
		return &user.StartReactivateUserResp{
			Op:              handlerError,
			TargetUserId:    "",
			AllowedReactive: false,
		}, err
	}

	return &user.StartReactivateUserResp{
		Op: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "请求成功",
			RequestId: requestId,
			Timestamp: time.Now().String(),
			Version:   0,
		},
		TargetUserId:    targetUserId,
		AllowedReactive: allow,
	}, nil
}

// ReactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) ReactivateUser(ctx context.Context, req *user.ReactivateUserReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, req.Version)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, req.Version)

	if err != nil {
		return res, err
	}

	v, err := s.userService.ReactiveUser(ctx, targetUid, requestUid, int(req.Version), req.RequestId)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, req.RequestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "请求成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
		Version:   uint64(v),
	}, nil
}

// StartDeleteUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartDeleteUser(ctx context.Context, req *user.StartDeleteReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	requestId, err := s.userService.StartDeleteUser(ctx, targetUid, requestUid, service.QueryType(req.QueryType))
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}
	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
	}, nil
}

// DeleteUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) DeleteUser(ctx context.Context, req *user.DeleteUserReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId, 0)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId, 0)

	if err != nil {
		return res, err
	}

	err, requestId := s.userService.DeleteUser(ctx, targetUid, requestUid, req.VerificationCode, req.RequestId)
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId, 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "注销成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
	}, nil
}

// GetVersion implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetVersion(ctx context.Context, req *user.VersionReq) (resp *user.OperationResult, err error) {
	res, err, userId := unmarshalUID(ctx, req.UserId, 0)

	if err != nil {
		return res, err
	}

	version, err := s.userService.GetVersion(ctx, userId)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, "", 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "获取成功",
		RequestId: "",
		Timestamp: time.Now().String(),
		Version:   uint64(version),
	}, nil
}

// AddVersion implements the UserServiceImpl interface.
func (s *UserServiceImpl) AddVersion(ctx context.Context, req *user.VersionReq) (resp *user.OperationResult, err error) {
	res, err, userId := unmarshalUID(ctx, req.UserId, 0)

	if err != nil {
		return res, err
	}

	if err = s.userService.AddVersion(ctx, userId); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "", 0)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改成功",
		RequestId: "",
		Timestamp: time.Now().String(),
	}, nil
}
