package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/123508/xservergo/apps/gateway/handlers/auth"
	"github.com/123508/xservergo/apps/gateway/handlers/user"
	"github.com/123508/xservergo/apps/gateway/middleware"
	"github.com/123508/xservergo/pkg/config"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	// 启动 Prometheus metrics 服务器
	go func() {
		defer wg.Done()
		metricsAddr := fmt.Sprintf("%s:%d", config.Conf.HertzConfig.Host, 10000)
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("Prometheus metrics server starting on %s", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			log.Printf("Prometheus metrics server error: %v", err)
		}
	}()

	// 启动主服务
	go func() {
		defer wg.Done()
		hertzAddr := fmt.Sprintf("%s:%d", config.Conf.HertzConfig.Host, config.Conf.HertzConfig.Port)
		hz := server.New(server.WithHostPorts(hertzAddr))

		// 注册 Prometheus 中间件
		middleware.RegisterPrometheus(hz)

		// 用户服务
		userGroup := hz.Group("/user")
		//注册用户
		userGroup.POST("/register", user.Register)
		//邮箱登录
		userGroup.POST("/email_login", user.EmailLogin)
		//手机号登录
		userGroup.POST("/phone_login", user.PhoneLogin)
		//账户登录
		userGroup.POST("/account_login", user.AccountLogin)
		//验证码登录
		userGroup.POST("/sms_login", user.SmsLogin)
		//二维码扫码登录
		userGroup.POST("/generate_qrCode", user.GenerateQrCode)
		userGroup.POST("/qr_pre_login", user.QrPreLogin)
		userGroup.POST("/qr_login", user.QrLogin)
		//忘记密码
		userGroup.POST("/forget_pwd", user.ForgetPassword)
		userGroup.POST("/reset_pwd", user.ResetPassword)
		//解析token
		userGroup.Use(middleware.ParseToken())
		//刷新token
		userGroup.Use(middleware.RefreshToken())
		//扫码登录移动端部分
		userGroup.POST("/qr_mobile_pre_login", user.QrMobilePreLogin)
		userGroup.POST("/qr_mobile_confirm_login", user.ConfirmQrLogin)
		userGroup.POST("/qr_mobile_cancel_login", user.CancelQrLogin)
		//登出
		userGroup.POST("/logout", user.Logout)
		//修改密码
		userGroup.POST("/change_pwd", user.ChangePassword)
		//绑定邮箱
		userGroup.POST("/start_bind_email", user.StartBindEmail)
		userGroup.POST("/complete_bind_email", user.CompleteBindEmail)
		//换绑邮箱
		userGroup.POST("/start_change_email", user.StartChangeEmail)
		userGroup.POST("/verify_new_email", user.VerifyNewEmail)
		userGroup.POST("/complete_change_email", user.CompleteChangeEmail)
		//绑定手机号
		userGroup.POST("/start_bind_phone", user.StartBindPhone)
		userGroup.POST("/complete_bind_phone", user.CompleteBindPhone)
		//换绑手机号
		userGroup.POST("/start_change_phone", user.StartChangePhone)
		userGroup.POST("/verify_new_phone", user.VerifyNewPhone)
		userGroup.POST("/complete_change_phone", user.CompleteChangePhone)
		//获取用户信息
		userGroup.POST("/get_userinfo_id", user.GetUserInfoById)
		userGroup.POST("/get_userinfo_others", user.GetUserInfoByOthers)
		//更新用户信息
		userGroup.POST("/update_userinfo", user.UpdateUserinfo)

		// 认证服务
		authGroup := hz.Group("/auth")
		// 解析token
		authGroup.Use(middleware.ParseToken())
		// 刷新token
		authGroup.Use(middleware.RefreshToken())
		// 权限管理
		authGroup.GET("/permission/:perm_code", auth.GetPermission)
		authGroup.GET("/permission", auth.GetPermissions)
		authGroup.POST("/permission", auth.CreatePermission)
		authGroup.PUT("/permission/:perm_code", auth.UpdatePermission)
		authGroup.DELETE("/permission/:perm_code", auth.DeletePermission)

		// 角色管理
		authGroup.POST("/role", auth.CreateRole)
		authGroup.GET("/role", auth.ListRoles)
		authGroup.GET("/role/:role_code", auth.GetRole)
		authGroup.PUT("/role/:role_code", auth.UpdateRole)
		authGroup.DELETE("/role/:role_code", auth.DeleteRole)

		// 角色权限管理
		authGroup.GET("/role/:role_code/permission", auth.GetRolePermissions)
		authGroup.POST("/role/:role_code/permission", auth.GrantPermissionToRole)
		authGroup.DELETE("/role/:role_code/permission", auth.RevokePermissionFromRole)

		// 用户角色管理
		authGroup.GET("/user/:user_id/role", auth.GetUserRoles)
		authGroup.POST("/user/:user_id/role", auth.AssignRoleToUser)
		authGroup.DELETE("/user/:user_id/role", auth.RemoveRoleFromUser)

		// 用户组管理
		authGroup.POST("/group", auth.CreateUserGroup)
		authGroup.GET("/group", auth.ListUserGroups)
		authGroup.GET("/group/:group_code", auth.GetUserGroup)
		authGroup.PUT("/group/:group_code", auth.UpdateUserGroup)
		authGroup.DELETE("/group/:group_code", auth.DeleteUserGroup)
		authGroup.GET("/group/:group_code/members", auth.GetUserGroupMembers)
		authGroup.GET("/group/:group_code/permissions", auth.GetUserGroupPermissions)

		// 用户组角色管理
		authGroup.POST("/group/:group_code/role", auth.AssignRoleToUserGroup)
		authGroup.DELETE("/group/:group_code/role", auth.RemoveRoleFromUserGroup)

		// 用户-用户组管理
		authGroup.GET("/user/:user_id/group", auth.GetUserGroups)
		authGroup.POST("/group/:group_code/member", auth.AssignUserToGroup)
		authGroup.DELETE("/group/:group_code/member", auth.RemoveUserFromGroup)

		// 用户权限
		authGroup.GET("/user/:user_id/permission", auth.GetUserPermissions)

		if err := hz.Run(); err != nil {
			panic(err)
		}

		fmt.Printf("网关服务启动成功")
	}()

	// 等待所有服务启动
	wg.Wait()
}
