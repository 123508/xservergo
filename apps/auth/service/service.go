package service

import (
	"context"
	"net/http"
	"time"

	"github.com/123508/xservergo/apps/auth/repo"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/config"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthService interface {
	GetRedis() *redis.Client

	// IssueToken 分发Token
	IssueToken(ctx context.Context, uid util.UUID) (models.Token, error)
	// RefreshToken 刷新Token
	RefreshToken(ctx context.Context, token models.Token, uid util.UUID) (models.Token, error)
	// VerifyToken 验证Token
	VerifyToken(ctx context.Context, accessToken string) (util.UUID, []string, uint64, error)

	// CreatePermission 创建权限
	CreatePermission(ctx context.Context, permission *models.Permission, operatorId util.UUID) (*models.Permission, error)
	// UpdatePermission 更新权限
	UpdatePermission(ctx context.Context, permission *models.Permission, operatorId util.UUID) (*models.Permission, error)
	// DeletePermission 删除权限
	DeletePermission(ctx context.Context, permissionCode string, operatorId util.UUID) error
	// GetPermissionByCode 获取权限
	GetPermissionByCode(ctx context.Context, permissionCode string) (*models.Permission, error)

	// CreateRole 创建角色
	CreateRole(ctx context.Context, role *models.Role, operatorId util.UUID) (*models.Role, error)
	// UpdateRole 更新角色
	UpdateRole(ctx context.Context, role *models.Role, operatorId util.UUID) (*models.Role, error)
	// DeleteRole 删除角色
	DeleteRole(ctx context.Context, roleCode string, operatorId util.UUID) error
	// GetRoleByCode 获取角色
	GetRoleByCode(ctx context.Context, roleCode string) (*models.Role, error)

	// GrantPermissionToRole 授权权限到角色
	GrantPermissionToRole(ctx context.Context, permissionCode, roleCode string, operatorId util.UUID) error
	// RevokePermissionFromRole 从角色撤销权限
	RevokePermissionFromRole(ctx context.Context, permissionCode, roleCode string, operatorId util.UUID) error
	// GetRolePermissions 获取角色权限
	GetRolePermissions(ctx context.Context, roleCode string) ([]string, error)

	// AssignRoleToUser 分配角色到用户
	AssignRoleToUser(ctx context.Context, roleCode string, userID util.UUID, operatorId util.UUID) error
	// RevokeRoleFromUser 从用户撤销角色
	RevokeRoleFromUser(ctx context.Context, roleCode string, userID util.UUID, operatorId util.UUID) error
	// GetUserRoles 获取用户角色
	GetUserRoles(ctx context.Context, userID util.UUID) ([]string, error)

	// CreateUserGroup 创建用户组
	CreateUserGroup(ctx context.Context, userGroup *models.UserGroup, operatorId util.UUID) (*models.UserGroup, error)
	// UpdateUserGroup 更新用户组
	UpdateUserGroup(ctx context.Context, userGroup *models.UserGroup, operatorId util.UUID) (*models.UserGroup, error)
	// DeleteUserGroup 删除用户组
	DeleteUserGroup(ctx context.Context, groupName string, operatorId util.UUID) error
	// GetUserGroupByName 获取用户组
	GetUserGroupByName(ctx context.Context, groupName string) (*models.UserGroup, error)
	// GetUserGroupMembers 获取用户组成员
	GetUserGroupMembers(ctx context.Context, groupName string) ([]util.UUID, error)
	// AssignRoleToUserGroup 分配角色到用户组
	AssignRoleToUserGroup(ctx context.Context, roleCode, groupName string, operatorId util.UUID) error
	// RemoveRoleFromUserGroup 从用户组撤销角色
	RemoveRoleFromUserGroup(ctx context.Context, roleCode, groupName string, operatorId util.UUID) error
	// GetUserGroupPermissions 获取用户组权限
	GetUserGroupPermissions(ctx context.Context, groupName string) ([]string, error)

	// AssignUserToGroup 分配用户到用户组
	AssignUserToGroup(ctx context.Context, userID util.UUID, groupName string, operatorId util.UUID) error
	// RevokeUserFromGroup 从用户组撤销用户
	RevokeUserFromGroup(ctx context.Context, userID util.UUID, groupName string, operatorId util.UUID) error
	// GetUserGroups 获取用户组
	GetUserGroups(ctx context.Context, userID util.UUID) ([]string, error)

	// GetUserPermissions 获取用户权限
	GetUserPermissions(ctx context.Context, userID util.UUID) ([]string, error)
	// HasPermission 检查用户是否有某个权限
	HasPermission(ctx context.Context, userID util.UUID, permissionCode string) bool
	// CanAccess 检查用户是否可以访问某个资源
	CanAccess(ctx context.Context, userID util.UUID, resource string, method string) bool

	// GetRoleList 获取角色列表
	GetRoleList(ctx context.Context, page, pageSize uint32) ([]*models.Role, error)
	// GetPermissionList 获取权限列表
	GetPermissionList(ctx context.Context, page, pageSize uint32) ([]*models.Permission, error)
	// GetUserGroupList 获取用户组列表
	GetUserGroupList(ctx context.Context, page, pageSize uint32) ([]*models.UserGroup, error)
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
		return models.Token{}, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	if b, err := s.Rds.Get(ctx, token.RefreshToken).Bool(); err != nil || !b {
		return models.Token{}, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
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
		return util.NewUUID(), nil, 0, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	if b, err := s.Rds.Get(ctx, accessToken).Bool(); err == nil && b {
		return util.NewUUID(), nil, 0, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	claims, err := ParseJWT(accessToken)

	if err != nil {
		return util.NewUUID(), nil, 0, cerrors.NewCommonError(http.StatusBadRequest, "请求参数错误", "", nil)
	}

	return claims.UserId, claims.Perms, claims.PVer, nil
}

func (s *ServiceImpl) CreatePermission(ctx context.Context, permission *models.Permission, operatorId util.UUID) (*models.Permission, error) {
	if permission == nil || permission.Code == "" || permission.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permission.AuditFields.CreatedBy = &operatorId
	err := s.authRepo.CreatePermission(permission)
	if err != nil {
		logs.ErrorLogger.Error("创建权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "创建权限错误", "", err)
	}

	newPermission, err := s.authRepo.GetPermissionByCode(permission.Code)
	return newPermission, nil
}

func (s *ServiceImpl) UpdatePermission(ctx context.Context, permission *models.Permission, operatorId util.UUID) (*models.Permission, error) {
	if permission == nil || permission.Code == "" || permission.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	existingPermission, err := s.authRepo.GetPermissionByCode(permission.Code)
	if err != nil {
		logs.ErrorLogger.Error("获取权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取权限错误", "", err)
	}

	permission.ID = existingPermission.ID
	permission.AuditFields.UpdatedBy = &operatorId

	err = s.authRepo.UpdatePermission(permission)
	if err != nil {
		logs.ErrorLogger.Error("更新权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "更新权限错误", "", err)
	}

	return permission, nil
}

func (s *ServiceImpl) DeletePermission(ctx context.Context, permissionCode string, operatorId util.UUID) error {
	if permissionCode == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.DeletePermission(permissionCode)
	if err != nil {
		logs.ErrorLogger.Error("删除权限错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "删除权限错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetPermissionByCode(ctx context.Context, permissionCode string) (*models.Permission, error) {
	if permissionCode == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permission, err := s.authRepo.GetPermissionByCode(permissionCode)
	if err != nil {
		logs.ErrorLogger.Error("获取权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取权限错误", "", err)
	}

	return permission, nil
}

func (s *ServiceImpl) CreateRole(ctx context.Context, role *models.Role, operatorId util.UUID) (*models.Role, error) {
	if role == nil || role.Code == "" || role.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	role.AuditFields.CreatedBy = &operatorId
	err := s.authRepo.CreateRole(role)
	if err != nil {
		logs.ErrorLogger.Error("创建角色错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "创建角色错误", "", err)
	}

	newRole, err := s.authRepo.GetRoleByCode(role.Code)
	return newRole, nil
}

func (s *ServiceImpl) UpdateRole(ctx context.Context, role *models.Role, operatorId util.UUID) (*models.Role, error) {
	if role == nil || role.Code == "" || role.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	existingRole, err := s.authRepo.GetRoleByCode(role.Code)
	if err != nil {
		logs.ErrorLogger.Error("获取角色错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取角色错误", "", err)
	}

	role.ID = existingRole.ID
	role.AuditFields.UpdatedBy = &operatorId

	err = s.authRepo.UpdateRole(role)
	if err != nil {
		logs.ErrorLogger.Error("更新角色错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "更新角色错误", "", err)
	}

	return role, nil
}

func (s *ServiceImpl) DeleteRole(ctx context.Context, roleCode string, operatorId util.UUID) error {
	if roleCode == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.DeleteRole(roleCode)
	if err != nil {
		logs.ErrorLogger.Error("删除角色错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "删除角色错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetRoleByCode(ctx context.Context, roleCode string) (*models.Role, error) {
	if roleCode == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	role, err := s.authRepo.GetRoleByCode(roleCode)
	if err != nil {
		logs.ErrorLogger.Error("获取角色错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取角色错误", "", err)
	}

	return role, nil
}

func (s *ServiceImpl) GrantPermissionToRole(ctx context.Context, permissionCode, roleCode string, operatorId util.UUID) error {
	if permissionCode == "" || roleCode == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.GrantPermissionToRole(permissionCode, roleCode)
	if err != nil {
		logs.ErrorLogger.Error("授权权限到角色错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "授权权限到角色错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) RevokePermissionFromRole(ctx context.Context, permissionCode, roleCode string, operatorId util.UUID) error {
	if permissionCode == "" || roleCode == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.RevokePermissionFromRole(permissionCode, roleCode)
	if err != nil {
		logs.ErrorLogger.Error("撤销权限从角色错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "撤销权限从角色错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetRolePermissions(ctx context.Context, roleCode string) ([]string, error) {
	if roleCode == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permissions, err := s.authRepo.GetRolePermission(roleCode)
	if err != nil {
		logs.ErrorLogger.Error("获取角色权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取角色权限错误", "", err)
	}

	return permissions, nil
}

func (s *ServiceImpl) AssignRoleToUser(ctx context.Context, roleCode string, userID util.UUID, operatorId util.UUID) error {
	if roleCode == "" || userID.IsZero() {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.AssignRoleToUser(roleCode, userID)
	if err != nil {
		logs.ErrorLogger.Error("分配角色到用户错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "分配角色到用户错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) RevokeRoleFromUser(ctx context.Context, roleCode string, userID util.UUID, operatorId util.UUID) error {
	if roleCode == "" || userID.IsZero() {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.RevokeRoleFromUser(roleCode, userID)
	if err != nil {
		logs.ErrorLogger.Error("从用户撤销角色错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "从用户撤销角色错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetUserRoles(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID.IsZero() {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	roles, err := s.authRepo.GetUserRoles(userID)
	if err != nil {
		logs.ErrorLogger.Error("获取用户角色错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户角色错误", "", err)
	}

	return roles, nil
}

func (s *ServiceImpl) CreateUserGroup(ctx context.Context, userGroup *models.UserGroup, operatorId util.UUID) (*models.UserGroup, error) {
	if userGroup == nil || userGroup.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	userGroup.AuditFields.CreatedBy = &operatorId
	err := s.authRepo.CreateUserGroup(userGroup)
	if err != nil {
		logs.ErrorLogger.Error("创建用户组错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "创建用户组错误", "", err)
	}

	newUserGroup, err := s.authRepo.GetUserGroupByName(userGroup.Name)
	return newUserGroup, nil
}

func (s *ServiceImpl) UpdateUserGroup(ctx context.Context, userGroup *models.UserGroup, operatorId util.UUID) (*models.UserGroup, error) {
	if userGroup == nil || userGroup.Name == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	existingGroup, err := s.authRepo.GetUserGroupByName(userGroup.Name)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组错误", "", err)
	}

	userGroup.ID = existingGroup.ID
	userGroup.AuditFields.UpdatedBy = &operatorId

	err = s.authRepo.UpdateUserGroup(userGroup)
	if err != nil {
		logs.ErrorLogger.Error("更新用户组错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "更新用户组错误", "", err)
	}

	return userGroup, nil
}

func (s *ServiceImpl) DeleteUserGroup(ctx context.Context, groupName string, operatorId util.UUID) error {
	if groupName == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.DeleteUserGroup(groupName)
	if err != nil {
		logs.ErrorLogger.Error("删除用户组错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "删除用户组错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetUserGroupByName(ctx context.Context, groupName string) (*models.UserGroup, error) {
	if groupName == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	userGroup, err := s.authRepo.GetUserGroupByName(groupName)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组错误", "", err)
	}

	return userGroup, nil
}

func (s *ServiceImpl) GetUserGroupMembers(ctx context.Context, groupName string) ([]util.UUID, error) {
	if groupName == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	members, err := s.authRepo.GetUserGroupMembers(groupName)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组成员错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组成员错误", "", err)
	}

	return members, nil
}

func (s *ServiceImpl) AssignRoleToUserGroup(ctx context.Context, roleCode, groupName string, operatorId util.UUID) error {
	if roleCode == "" || groupName == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.AssignRoleToUserGroup(roleCode, groupName)
	if err != nil {
		logs.ErrorLogger.Error("分配角色到用户组错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "分配角色到用户组错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) RemoveRoleFromUserGroup(ctx context.Context, roleCode, groupName string, operatorId util.UUID) error {
	if roleCode == "" || groupName == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.RemoveRoleFromUserGroup(roleCode, groupName)
	if err != nil {
		logs.ErrorLogger.Error("从用户组撤销角色错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "从用户组撤销角色错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetUserGroupPermissions(ctx context.Context, groupName string) ([]string, error) {
	if groupName == "" {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permissions, err := s.authRepo.GetUserGroupPermissions(groupName)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组权限错误", "", err)
	}

	return permissions, nil
}

func (s *ServiceImpl) AssignUserToGroup(ctx context.Context, userID util.UUID, groupName string, operatorId util.UUID) error {
	if userID.IsZero() || groupName == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.AssignUserToGroup(userID, groupName)
	if err != nil {
		logs.ErrorLogger.Error("分配用户到用户组错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "分配用户到用户组错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) RevokeUserFromGroup(ctx context.Context, userID util.UUID, groupName string, operatorId util.UUID) error {
	if userID.IsZero() || groupName == "" {
		return cerrors.NewParamError("请求参数错误")
	}

	err := s.authRepo.RevokeUserFromGroup(userID, groupName)
	if err != nil {
		logs.ErrorLogger.Error("从用户组撤销用户错误:", zap.Error(err))
		return cerrors.NewCommonError(http.StatusInternalServerError, "从用户组撤销用户错误", "", err)
	}

	return nil
}

func (s *ServiceImpl) GetUserGroups(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID.IsZero() {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	groups, err := s.authRepo.GetUserGroups(userID)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组错误", "", err)
	}

	return groups, nil
}

func (s *ServiceImpl) GetUserPermissions(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID.IsZero() {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permissions, err := s.authRepo.GetUserPermissions(userID)
	if err != nil {
		logs.ErrorLogger.Error("获取用户权限错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户权限错误", "", err)
	}

	return permissions, nil
}

func (s *ServiceImpl) HasPermission(ctx context.Context, userID util.UUID, permissionCode string) bool {
	if userID.IsZero() || permissionCode == "" {
		return false
	}

	permissions, err := s.authRepo.GetUserPermissions(userID)
	if err != nil {
		logs.ErrorLogger.Error("获取用户权限错误:", zap.Error(err))
		return false
	}

	for _, perm := range permissions {
		if perm == permissionCode {
			return true
		}
	}

	return false
}

func (s *ServiceImpl) CanAccess(ctx context.Context, userID util.UUID, resource string, method string) bool {
	if userID.IsZero() || resource == "" || method == "" {
		return false
	}

	res := s.authRepo.CanAccess(userID, resource, method)

	return res
}

func (s *ServiceImpl) GetRoleList(ctx context.Context, page, pageSize uint32) ([]*models.Role, error) {
	if pageSize == 0 {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	roles, err := s.authRepo.GetRoleList(page, pageSize)
	if err != nil {
		logs.ErrorLogger.Error("获取角色列表错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取角色列表错误", "", err)
	}

	return roles, nil
}

func (s *ServiceImpl) GetPermissionList(ctx context.Context, page, pageSize uint32) ([]*models.Permission, error) {
	if pageSize == 0 {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	permissions, err := s.authRepo.GetPermissionList(page, pageSize)
	if err != nil {
		logs.ErrorLogger.Error("获取权限列表错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取权限列表错误", "", err)
	}

	return permissions, nil
}

func (s *ServiceImpl) GetUserGroupList(ctx context.Context, page, pageSize uint32) ([]*models.UserGroup, error) {
	if pageSize == 0 {
		return nil, cerrors.NewParamError("请求参数错误")
	}

	userGroups, err := s.authRepo.GetUserGroupList(page, pageSize)
	if err != nil {
		logs.ErrorLogger.Error("获取用户组列表错误:", zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "获取用户组列表错误", "", err)
	}

	return userGroups, nil
}
