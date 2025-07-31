package main

import (
	"context"
	"github.com/123508/xservergo/apps/user/service"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/component/serializer"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"net/http"
	"time"

	"github.com/123508/xservergo/kitex_gen/user"
)

func parseServiceErrToHandlerError(ctx context.Context, err error, requestId string) (*user.OperationResult, error) {

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
	}

	if requestId != "" {
		resp.RequestId = requestId
	}

	return resp, cerrors.NewGRPCError(code, message)
}

func unmarshalUID(ctx context.Context, uid []byte) (*user.OperationResult, error, util.UUID) {

	Uid := util.NewUUID()
	if err := Uid.Unmarshal(uid); err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误"), Uid
	}

	return nil, nil, Uid
}

func marshalUID(ctx context.Context, uid util.UUID) (*user.OperationResult, error, []byte) {
	marshal, err := uid.Marshal()

	if err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusInternalServerError,
			Message:   "序列化失败",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化失败"), marshal
	}
	return nil, nil, marshal
}

// UserServiceImpl implements the last service interface defined in the IDL.
type UserServiceImpl struct {
	userService service.UserService
}

func NewUserServiceImpl(database *gorm.DB, rds *redis.Client) *UserServiceImpl {
	return &UserServiceImpl{
		userService: service.NewService(database, rds),
	}
}

// Register implements the UserServiceImpl interface.
func (s *UserServiceImpl) Register(ctx context.Context, req *user.RegisterReq) (resp *user.OperationResult, err error) {

	u := &models.User{
		NickName: req.Nickname,
		UserName: req.Username,
		Email:    req.Email,
		Phone:    req.Phone,
		Gender:   req.Gender,
		Status:   0,
		AuditFields: models.AuditFields{
			CreatedAt: time.Now(),
			Version:   0,
		},
	}

	uLogin := &models.UserLogin{
		Password: req.Password,
		AuditFields: models.AuditFields{
			CreatedAt: time.Now(),
			Version:   0,
		},
	}

	if err = s.userService.Register(ctx, u, uLogin); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "")
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "创建用户成功",
		Timestamp: time.Now().String(),
	}, err
}

// EmailLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) EmailLogin(ctx context.Context, req *user.EmailLoginReq) (resp *user.LoginResp, err error) {

	login, token, err := s.userService.EmailLogin(ctx, req.Email, req.Password)

	resp = &user.LoginResp{}

	if err != nil {
		_, err := parseServiceErrToHandlerError(ctx, err, "")
		return &user.LoginResp{}, err
	}

	_, err, marshal := marshalUID(ctx, login.ID)

	if err != nil {
		return &user.LoginResp{}, err
	}

	return &user.LoginResp{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		UserInfo: &user.UserInfo{
			UserId:   marshal,
			Nickname: login.NickName,
			Email:    login.Email,
			Avatar:   login.Avatar,
		},
	}, err
}

// PhoneLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) PhoneLogin(ctx context.Context, req *user.PhoneLoginReq) (resp *user.LoginResp, err error) {

	login, token, err := s.userService.PhoneLogin(ctx, req.Phone, req.Password)

	resp = &user.LoginResp{}

	if err != nil {

		com, ok := err.(*cerrors.CommonError)

		if ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "用户登录失败")
		}

	} else {
		marshal, err := login.ID.Marshal()

		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器出错")
		}

		resp.AccessToken = token.AccessToken
		resp.RefreshToken = token.RefreshToken
		resp.UserInfo = &user.UserInfo{
			UserId:   marshal,
			Nickname: login.NickName,
			Email:    login.Email,
			Avatar:   login.Avatar,
		}
	}

	return resp, err
}

// AccountLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) AccountLogin(ctx context.Context, req *user.AccountLoginReq) (resp *user.LoginResp, err error) {
	login, token, err := s.userService.UserNameLogin(ctx, req.Username, req.Password)

	resp = &user.LoginResp{}

	if err != nil {

		com, ok := err.(*cerrors.CommonError)

		if ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "用户登录失败")
		}

	} else {
		marshal, err := login.ID.Marshal()

		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器出错")
		}

		resp.AccessToken = token.AccessToken
		resp.RefreshToken = token.RefreshToken
		resp.UserInfo = &user.UserInfo{
			UserId:   marshal,
			Nickname: login.NickName,
			Email:    login.Email,
			Avatar:   login.Avatar,
		}
	}

	return resp, err
}

// SmsLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) SmsLogin(ctx context.Context, req *user.SmsLoginReq) (resp *user.SmsLoginResp, err error) {
	if req.Flow == 0 {
		requestId, err := s.userService.SmsSendCode(ctx, req.Phone)
		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "发送验证码错误")
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
				return nil, cerrors.NewGRPCError(com.Code, com.Message)
			} else {
				return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "登录失败")
			}
		}

		marshal, err := login.ID.Marshal()

		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化错误")
		}

		return &user.SmsLoginResp{
			Result: &user.SmsLoginResp_Login{
				Login: &user.LoginResp{
					RefreshToken: token.RefreshToken,
					AccessToken:  token.AccessToken,
					UserInfo: &user.UserInfo{
						UserId:   marshal,
						Nickname: login.NickName,
						Email:    login.Email,
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
			if marshal, Err := uid.Marshal(); Err != nil {
				resp.Ok = false
				err = cerrors.NewGRPCError(http.StatusInternalServerError, "序列化失败")
			} else {
				resp.Ok = status
				resp.UserId = marshal
			}
		} else {
			resp.Ok = false
		}
	}
	return resp, err
}

// QrCodeLoginStatus implements the UserServiceImpl interface.
func (s *UserServiceImpl) QrCodeLoginStatus(ctx context.Context, req *user.QrCodeLoginStatusReq) (resp *user.QrCodeLoginStatusResp, err error) {

	_, err, uid := unmarshalUID(ctx, req.UserId)
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
							Nickname: usr.NickName,
							Email:    usr.Email,
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

	_, err, uid := unmarshalUID(ctx, req.UserId)

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

	_, err, uid := unmarshalUID(ctx, req.UserId)
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

	_, err, uid := unmarshalUID(ctx, req.UserId)

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
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return res, err
	}

	if err = s.userService.Logout(ctx, requestUid, targetUid, &models.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
	}); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "")
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "成功退出",
		Timestamp: time.Now().String(),
	}, nil

}

// SessionCheck implements the UserServiceImpl interface.
func (s *UserServiceImpl) SessionCheck(ctx context.Context, req *user.SessionCheckReq) (resp *user.SessionStatusResp, err error) {
	// TODO: Your code here...
	return
}

// ChangePassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ChangePassword(ctx context.Context, req *user.ChangePasswordReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return res, err
	}

	if err = s.userService.ChangePassword(ctx, targetUid, requestUid, req.OldPassword, req.NewPassword); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "")
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "修改密码成功",
		Timestamp: time.Now().String(),
	}, nil
}

// ForgotPassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ForgotPassword(ctx context.Context, req *user.ForgotPasswordReq) (resp *user.OperationResult, err error) {
	var ok bool
	var uid util.UUID
	var requestId string

	if req.GetUsername() != "" {
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, req.GetUsername(), service.USERNAME, serializer.JSON, req.Type)
	} else if req.GetEmail() != "" {
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, req.GetEmail(), service.EMAIL, serializer.JSON, req.Type)
	} else if req.GetPhone() != "" {
		ok, uid, requestId, err = s.userService.ForgetPassword(ctx, req.GetPhone(), service.PHONE, serializer.JSON, req.Type)
	} else {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId)
	}

	res, err, marshal := marshalUID(ctx, uid)

	if err != nil {
		return res, err
	}

	return &user.OperationResult{
		Success:       ok,
		Code:          http.StatusOK,
		Message:       "成功",
		RequestId:     requestId,
		Timestamp:     time.Now().String(),
		RequestUserId: marshal,
	}, nil
}

// ResetPassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ResetPassword(ctx context.Context, req *user.ResetPasswordReq) (resp *user.OperationResult, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return res, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return res, err
	}

	if err = s.userService.ResetPassword(ctx, targetUid, requestUid, req.NewPassword, req.RequestId, req.VerificationToken); err != nil {
		return parseServiceErrToHandlerError(ctx, err, "")
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "更新成功",
		RequestId: req.RequestId,
		Timestamp: time.Now().String(),
	}, nil
}

// StartBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartBindEmail(ctx context.Context, req *user.StartBindEmailReq) (resp *user.OperationResult, err error) {

	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartBindEmail(ctx, targetUid, requestUid, req.NewEmail)
	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
	}, nil
}

// CompleteBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindEmail(ctx context.Context, req *user.CompleteBindEmailReq) (resp *user.CompleteBindEmailResp, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return &user.CompleteBindEmailResp{
			Operation: res,
			Version:   req.Version,
		}, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return &user.CompleteBindEmailResp{
			Operation: res,
			Version:   req.Version,
		}, err
	}

	v, err := s.userService.CompleteBindEmail(ctx, targetUid, requestUid, req.NewEmail, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		res, err := parseServiceErrToHandlerError(ctx, err, "")
		return &user.CompleteBindEmailResp{
			Operation: res,
			Version:   uint64(v),
		}, err
	}
	return &user.CompleteBindEmailResp{
		Operation: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "绑定成功",
			RequestId: req.RequestId,
			Timestamp: time.Now().String(),
		},
		Version: uint64(v),
	}, nil
}

// StartChangeEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartChangeEmail(ctx context.Context, req *user.StartChangeEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// VerifyNewEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) VerifyNewEmail(ctx context.Context, req *user.VerifyNewEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// CompleteChangeEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteChangeEmail(ctx context.Context, req *user.CompleteChangeEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// StartBindPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartBindPhone(ctx context.Context, req *user.StartBindPhoneReq) (resp *user.OperationResult, err error) {
	resp, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return resp, err
	}

	resp, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return resp, err
	}

	requestId, err := s.userService.StartBindPhone(ctx, targetUid, requestUid, req.NewPhone)

	if err != nil {
		return parseServiceErrToHandlerError(ctx, err, requestId)
	}

	return &user.OperationResult{
		Success:   true,
		Code:      http.StatusOK,
		Message:   "发送成功",
		RequestId: requestId,
		Timestamp: time.Now().String(),
	}, nil
}

// CompleteBindPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindPhone(ctx context.Context, req *user.CompleteBindPhoneReq) (resp *user.CompleteBindPhoneResp, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return &user.CompleteBindPhoneResp{
			Operation: res,
			Version:   req.Version,
		}, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return &user.CompleteBindPhoneResp{
			Operation: res,
			Version:   req.Version,
		}, err
	}

	v, err := s.userService.CompleteBindPhone(ctx, targetUid, requestUid, req.NewPhone, req.VerificationCode, req.RequestId, int(req.Version))

	if err != nil {
		res, err := parseServiceErrToHandlerError(ctx, err, "")
		return &user.CompleteBindPhoneResp{
			Operation: res,
			Version:   uint64(v),
		}, err
	}

	return &user.CompleteBindPhoneResp{
		Operation: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "修改成功",
			RequestId: req.RequestId,
			Timestamp: time.Now().String(),
		},
		Version: uint64(v),
	}, nil
}

// StartChangePhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartChangePhone(ctx context.Context, req *user.StartChangePhoneReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// VerifyNewPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) VerifyNewPhone(ctx context.Context, req *user.VerifyNewPhoneReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// CompleteChangePhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteChangePhone(ctx context.Context, req *user.CompleteChangePhoneReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetUserInfoById implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetUserInfoById(ctx context.Context, req *user.GetUserInfoByIdReq) (resp *user.UserInfoResp, err error) {
	res, err, targetUid := unmarshalUID(ctx, req.TargetUserId)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	userinfo, err := s.userService.GetUserInfoById(ctx, targetUid, requestUid)

	if err != nil {
		result, err := parseServiceErrToHandlerError(ctx, err, "")
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
			},
		}, cerrors.NewGRPCError(http.StatusForbidden, "用户不存在或已经删除")
	}

	res, err, marshal := marshalUID(ctx, userinfo.ID)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	return &user.UserInfoResp{
		Result: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "查询成功",
			Timestamp: time.Now().String(),
		},
		UserInfo: &user.UserInfo{
			UserId:   marshal,
			Username: userinfo.UserName,
			Nickname: userinfo.NickName,
			Email:    userinfo.Email,
			Phone:    userinfo.Phone,
			Gender:   userinfo.Gender,
			Avatar:   userinfo.Avatar,
		},
	}, nil
}

// GetUserInfoByOthers implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetUserInfoByOthers(ctx context.Context, req *user.GetUserInfoByOthersReq) (resp *user.UserInfoResp, err error) {

	res, err, requestUid := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	var userinfo *models.User

	if req.GetUsername() != "" {
		userinfo, err = s.userService.GetUserInfoBySpecialSig(ctx, req.GetUsername(), requestUid, service.USERNAME, serializer.JSON)
	} else if req.GetEmail() != "" {
		userinfo, err = s.userService.GetUserInfoBySpecialSig(ctx, req.GetEmail(), requestUid, service.EMAIL, serializer.JSON)
	} else if req.GetPhone() != "" {
		userinfo, err = s.userService.GetUserInfoBySpecialSig(ctx, req.GetPhone(), requestUid, service.PHONE, serializer.JSON)
	} else {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "参数错误",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}

	if err != nil {
		result, err := parseServiceErrToHandlerError(ctx, err, "")
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
			},
		}, cerrors.NewGRPCError(http.StatusForbidden, "用户不存在或已经删除")
	}

	//序列化部分
	res, err, marshal := marshalUID(ctx, userinfo.ID)

	if err != nil {
		return &user.UserInfoResp{
			Result: res,
		}, err
	}

	return &user.UserInfoResp{
		Result: &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "查询成功",
			Timestamp: time.Now().String(),
		},
		UserInfo: &user.UserInfo{
			UserId:   marshal,
			Username: userinfo.UserName,
			Nickname: userinfo.NickName,
			Email:    userinfo.Email,
			Phone:    userinfo.Phone,
			Gender:   userinfo.Gender,
			Avatar:   userinfo.Avatar,
		},
	}, nil
}

// UpdateUserInfo implements the UserServiceImpl interface.
func (s *UserServiceImpl) UpdateUserInfo(ctx context.Context, req *user.UpdateUserInfoReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// ListUsers implements the UserServiceImpl interface.
func (s *UserServiceImpl) ListUsers(ctx context.Context, req *user.ListUsersReq) (resp *user.ListUsersResp, err error) {
	// TODO: Your code here...
	return
}

// SearchUserByNickname implements the UserServiceImpl interface.
func (s *UserServiceImpl) SearchUserByNickname(ctx context.Context, req *user.SearchUserByNicknameReq) (resp *user.SearchUserByNicknameResp, err error) {
	// TODO: Your code here...
	return
}

// StartDeactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartDeactivateUser(ctx context.Context, req *user.StartDeactivateReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// DeactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) DeactivateUser(ctx context.Context, req *user.DeactivateUserReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// ReactivateUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) ReactivateUser(ctx context.Context, req *user.ReactivateUserReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// StartDeleteUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartDeleteUser(ctx context.Context, req *user.StartDeleteReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// DeleteUser implements the UserServiceImpl interface.
func (s *UserServiceImpl) DeleteUser(ctx context.Context, req *user.DeleteUserReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}
