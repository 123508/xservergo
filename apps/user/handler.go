package main

import (
	"context"
	"github.com/123508/xservergo/apps/user/service"
	user "github.com/123508/xservergo/kitex_gen/user"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
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
	// TODO: Your code here...
	return
}

// EmailLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) EmailLogin(ctx context.Context, req *user.EmailLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// PhoneLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) PhoneLogin(ctx context.Context, req *user.PhoneLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// AccountLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) AccountLogin(ctx context.Context, req *user.AccountLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// SmsLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) SmsLogin(ctx context.Context, req *user.SmsLoginReq) (resp *user.SmsLoginResp, err error) {
	// TODO: Your code here...
	return
}

// QrCodeLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) QrCodeLogin(ctx context.Context, req *user.QrCodeLoginReq) (resp *user.QrCodeLoginResp, err error) {
	// TODO: Your code here...
	return
}

// ConfirmQrLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) ConfirmQrLogin(ctx context.Context, req *user.ConfirmQrLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// OAuthLogin implements the UserServiceImpl interface.
func (s *UserServiceImpl) OAuthLogin(ctx context.Context, req *user.OAuthLoginReq) (resp *user.LoginResp, err error) {
	// TODO: Your code here...
	return
}

// Logout implements the UserServiceImpl interface.
func (s *UserServiceImpl) Logout(ctx context.Context, req *user.LogoutReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// SessionCheck implements the UserServiceImpl interface.
func (s *UserServiceImpl) SessionCheck(ctx context.Context, req *user.SessionCheckReq) (resp *user.SessionStatusResp, err error) {
	// TODO: Your code here...
	return
}

// ChangePassword implements the UserServiceImpl interface.
func (s *UserServiceImpl) ChangePassword(ctx context.Context, req *user.ChangePasswordReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
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

// StartUnbindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) StartUnbindEmail(ctx context.Context, req *user.StartUnbindEmailReq) (resp *user.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// CompleteUnbindEmail implements the UserServiceImpl interface.
func (s *UserServiceImpl) CompleteUnbindEmail(ctx context.Context, req *user.CompleteUnbindEmailReq) (resp *user.OperationResult, err error) {
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

// GetUserInfo implements the UserServiceImpl interface.
func (s *UserServiceImpl) GetUserInfo(ctx context.Context, req *user.GetUserInfoReq) (resp *user.UserInfoResp, err error) {
	// TODO: Your code here...
	return
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
