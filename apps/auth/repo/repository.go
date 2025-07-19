package repo

import (
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"gorm.io/gorm"
)

type AuthRepository interface {
	GetDB() *gorm.DB

	// CreatePermission 创建权限
	CreatePermission(permission *models.Permission) error
	// UpdatePermission 更新权限
	UpdatePermission(permission *models.Permission) error
	// DeletePermission 删除权限
	DeletePermission(permissionCode string) error
	// GetPermissionByID 根据权限ID获取权限
	GetPermissionByID(permissionID []byte) (*models.Permission, error)
	// GetPermissionByCode 根据权限代码获取权限
	GetPermissionByCode(permissionCode string) (*models.Permission, error)

	// CreateRole 创建角色
	CreateRole(role *models.Role) error
	// UpdateRole 更新角色
	UpdateRole(role *models.Role) error
	// DeleteRole 删除角色
	DeleteRole(roleCode string) error
	// GetRoleByID 根据角色ID获取角色
	GetRoleByID(roleID []byte) (*models.Role, error)
	// GetRoleByCode 根据角色代码获取角色
	GetRoleByCode(roleCode string) (*models.Role, error)

	// GrantPermissionToRole 授予权限给角色
	GrantPermissionToRole(permissionCode string, roleCode string) error
	// RevokePermissionFromRole 撤销角色的权限
	RevokePermissionFromRole(permissionCode string, roleCode string) error
	// GetRolePermission 获取角色的权限
	// 返回权限代码列表
	GetRolePermission(roleCode string) ([]string, error)

	// AssignRoleToUser 分配角色给用户
	AssignRoleToUser(roleCode string, username string) error
	// RevokeRoleFromUser 撤销用户的角色
	RevokeRoleFromUser(roleCode string, username string) error
	// GetUserRoles 获取用户的角色
	GetUserRoles(username string) ([]string, error)

	// CreateUserGroup 创建用户组
	CreateUserGroup(userGroup *models.UserGroup) error
	// UpdateUserGroup 更新用户组
	UpdateUserGroup(userGroup *models.UserGroup) error
	// DeleteUserGroup 删除用户组
	DeleteUserGroup(groupID string) error
	// GetUserGroupByID 根据用户组ID获取用户组
	GetUserGroupByID(groupID []byte) (*models.UserGroup, error)
	// GetUserGroupByName 根据用户组名称获取用户组
	GetUserGroupByName(groupName string) (*models.UserGroup, error)
	// GetUserGroupMembers 获取用户组成员
	// 返回成员用户名列表
	GetUserGroupMembers(groupName string) ([]string, error)
	// GetUserGroupPermissions 获取用户组的权限
	GetUserGroupPermissions(groupName string) ([]string, error)

	// AssignUserToGroup 分配用户到用户组
	AssignUserToGroup(username string, groupName string) error
	// RevokeUserFromGroup 撤销用户组中的用户
	RevokeUserFromGroup(username string, groupName string) error
	// GetUserGroups 获取用户所属的用户组
	// 返回用户组名称列表
	GetUserGroups(username string) ([]string, error)

	// GetUserPermissions 获取用户的权限
	// 返回权限代码列表
	GetUserPermissions(username string) ([]string, error)
	// HasPermission 检查用户是否有特定权限
	HasPermission(username string, permissionCode string) bool
	// CanAccess 检查用户是否可以以某种方法访问特定资源
	CanAccess(username string, resource string, method string) bool

	// GetRoleList 获取角色列表
	GetRoleList(page uint32, pageSize uint32) ([]*models.Role, error)
	// GetPermissionList 获取权限列表
	GetPermissionList(page uint32, pageSize uint32) ([]*models.Permission, error)
	// GetUserGroupList 获取用户组列表
	GetUserGroupList(page uint32, pageSize uint32) ([]*models.UserGroup, error)
}

type RepoImpl struct {
	DB *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &RepoImpl{
		DB: db,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}

func (r *RepoImpl) CreatePermission(permission *models.Permission) error {
	if permission == nil {
		return cerrors.NewParamError("permission cannot be nil")
	}

	if err := r.DB.Create(permission).Error; err != nil {
		return cerrors.NewSQLError("failed to create permission: ", err)
	}
	return nil
}

func (r *RepoImpl) UpdatePermission(permission *models.Permission) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) DeletePermission(permissionCode string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetPermissionByID(permissionID []byte) (*models.Permission, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetPermissionByCode(permissionCode string) (*models.Permission, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) CreateRole(role *models.Role) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) UpdateRole(role *models.Role) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) DeleteRole(roleCode string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetRoleByID(roleID []byte) (*models.Role, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetRoleByCode(roleCode string) (*models.Role, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GrantPermissionToRole(permissionCode string, roleCode string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) RevokePermissionFromRole(permissionCode string, roleCode string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetRolePermission(roleCode string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) AssignRoleToUser(roleCode string, username string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) RevokeRoleFromUser(roleCode string, username string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserRoles(username string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) CreateUserGroup(userGroup *models.UserGroup) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) UpdateUserGroup(userGroup *models.UserGroup) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) DeleteUserGroup(groupID string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroupByID(groupID []byte) (*models.UserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroupByName(groupName string) (*models.UserGroup, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroupMembers(groupName string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroupPermissions(groupName string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) AssignUserToGroup(username string, groupName string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) RevokeUserFromGroup(username string, groupName string) error {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroups(username string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserPermissions(username string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) HasPermission(username string, permissionCode string) bool {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) CanAccess(username string, resource string, method string) bool {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetRoleList(page uint32, pageSize uint32) ([]*models.Role, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetPermissionList(page uint32, pageSize uint32) ([]*models.Permission, error) {
	//TODO implement me
	panic("implement me")
}

func (r *RepoImpl) GetUserGroupList(page uint32, pageSize uint32) ([]*models.UserGroup, error) {
	//TODO implement me
	panic("implement me")
}
