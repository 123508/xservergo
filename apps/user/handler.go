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

	err = s.userService.Register(ctx, u, uLogin)

	if err == nil {
		resp = &user.OperationResult{
			Success:   true,
			Code:      http.StatusOK,
			Message:   "创建用户成功",
			Timestamp: time.Now().String(),
		}
	} else {
		com, ok := err.(*cerrors.CommonError)
		if !ok {
			resp = &user.OperationResult{
				Success:   false,
				Code:      http.StatusInternalServerError,
				Message:   "创建用户失败",
				Timestamp: time.Now().String(),
			}

		} else {
			resp = &user.OperationResult{
				Success:   false,
				Code:      com.Code,
				Message:   com.Message,
				Timestamp: time.Now().String(),
			}

			err = cerrors.NewGRPCError(com.Code, com.Message)
		}
	}
	return resp, err
}

// EmailLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) EmailLogin(ctx context.Context, req *user.EmailLoginReq) (resp *user.LoginResp, err error) {

	login, token, err := s.userService.EmailLogin(ctx, req.Email, req.Password)

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

	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
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

	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
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

	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
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

	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
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
	targetUid := util.NewUUID()
	if err = targetUid.Unmarshal(req.TargetUserId); err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	requestUid := util.NewUUID()
	if err = requestUid.Unmarshal(req.RequestUserId); err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	if err = s.userService.Logout(ctx, requestUid, targetUid, &models.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
	}); err != nil {
		var code uint64
		var message string
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
			code = com.Code
			message = com.Message
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "服务器错误")
			code = http.StatusInternalServerError
			message = "服务器错误"
		}
		return &user.OperationResult{
			Success:   false,
			Code:      code,
			Message:   message,
			Timestamp: time.Now().String(),
		}, err
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
	targetUid := util.NewUUID()
	if err = targetUid.Unmarshal(req.TargetUserId); err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	requestUid := util.NewUUID()
	if err = requestUid.Unmarshal(req.RequestUserId); err != nil {
		return &user.OperationResult{
			Success:   false,
			Code:      http.StatusBadRequest,
			Message:   "请求参数错误",
			Timestamp: time.Now().String(),
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	if err = s.userService.ChangePassword(ctx, targetUid, requestUid, req.OldPassword, req.NewPassword); err != nil {
		var code uint64
		var message string
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
			code = com.Code
			message = com.Message
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "服务器错误")
			code = http.StatusInternalServerError
			message = "服务器错误,修改密码失败"
		}
		return &user.OperationResult{
			Success:   false,
			Code:      code,
			Message:   message,
			Timestamp: time.Now().String(),
		}, err
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
	// TODO: Your code here...
	return
}

// ResetPassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ResetPassword(ctx context.Context, req *user.ResetPasswordReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// StartBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartBindEmail(ctx context.Context, req *user.StartBindEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// CompleteBindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindEmail(ctx context.Context, req *user.CompleteBindEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
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
	// TODO: Your code here...
	return
}

// CompleteBindPhone implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteBindPhone(ctx context.Context, req *user.CompleteBindPhoneReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
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
	requestUid := util.NewUUID()
	if err = requestUid.Unmarshal(req.RequestUserId); err != nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "参数错误",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}
	targetUid := util.NewUUID()
	if err = targetUid.Unmarshal(req.TargetUserId); err != nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "参数错误",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusBadRequest, "参数错误")
	}

	userinfo, err := s.userService.GetUserInfoById(ctx, targetUid, requestUid)
	if err != nil {
		var code uint64
		var message string
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
			code = com.Code
			message = com.Message
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
			code = http.StatusInternalServerError
			message = "服务器异常"
		}
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      code,
				Message:   message,
				Timestamp: time.Now().String(),
			},
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

	marshal, err := userinfo.ID.Marshal()

	if err != nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusInternalServerError,
				Message:   "序列化失败",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化失败")
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
	requestUid := util.NewUUID()
	if err = requestUid.Unmarshal(req.RequestUserId); err != nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusBadRequest,
				Message:   "参数错误",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
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
		var code uint64
		var message string
		if com, ok := err.(*cerrors.CommonError); ok {
			err = cerrors.NewGRPCError(com.Code, com.Message)
			code = com.Code
			message = com.Message
		} else {
			err = cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
			code = http.StatusInternalServerError
			message = "服务器异常"
		}
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      code,
				Message:   message,
				Timestamp: time.Now().String(),
			},
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

	marshal, err := userinfo.ID.Marshal()

	if err != nil {
		return &user.UserInfoResp{
			Result: &user.OperationResult{
				Success:   false,
				Code:      http.StatusInternalServerError,
				Message:   "序列化失败",
				Timestamp: time.Now().String(),
			},
		}, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化失败")
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

// VerifySecurityCode implements the UserServiceImpl interface.
func (s *UserServiceImpl) VerifySecurityCode(ctx context.Context, req *user.VerifyCodeReq) (resp *user.VerifyCodeResp, err error) {
	// TODO: Your code here...
	return
}

// SendVerification implements the UserServiceImpl interface.
func (s *UserServiceImpl) SendVerification(ctx context.Context, req *user.SendVerificationReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}
