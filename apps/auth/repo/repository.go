package repo

import (
	"context"
	"net/http"
	"time"

	"github.com/123508/xservergo/pkg/util"

	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"gorm.io/gorm"
)

type AuthRepository interface {
	GetDB() *gorm.DB

	// CreatePermission 创建权限
	CreatePermission(ctx context.Context, permission *models.Permission) error
	// UpdatePermission 更新权限
	UpdatePermission(ctx context.Context, permission *models.Permission) error
	// DeletePermission 删除权限
	DeletePermission(ctx context.Context, permissionCode string, operatorId *util.UUID) error
	// GetPermissionByID 根据权限ID获取权限
	GetPermissionByID(ctx context.Context, permissionID util.UUID) (*models.Permission, error)
	// GetPermissionByCode 根据权限代码获取权限
	GetPermissionByCode(ctx context.Context, permissionCode string) (*models.Permission, error)

	// CreateRole 创建角色
	CreateRole(ctx context.Context, role *models.Role) error
	// UpdateRole 更新角色
	UpdateRole(ctx context.Context, role *models.Role) error
	// DeleteRole 删除角色
	DeleteRole(ctx context.Context, roleCode string, operatorId *util.UUID) error
	// GetRoleByID 根据角色ID获取角色
	GetRoleByID(ctx context.Context, roleID []byte) (*models.Role, error)
	// GetRoleByCode 根据角色代码获取角色
	GetRoleByCode(ctx context.Context, roleCode string) (*models.Role, error)

	// GrantPermissionToRole 授予权限给角色
	GrantPermissionToRole(ctx context.Context, permissionCode string, roleCode string, operatorId *util.UUID) error
	// RevokePermissionFromRole 撤销角色的权限
	RevokePermissionFromRole(ctx context.Context, permissionCode string, roleCode string, operatorId *util.UUID) error
	// GetRolePermission 获取角色的权限
	// 返回权限代码列表
	GetRolePermission(ctx context.Context, roleCode string) ([]string, error)

	// AssignRoleToUser 分配角色给用户
	AssignRoleToUser(ctx context.Context, roleCode string, userID util.UUID, operatorId *util.UUID) error
	// RevokeRoleFromUser 撤销用户的角色
	RevokeRoleFromUser(ctx context.Context, roleCode string, userID util.UUID, operatorId *util.UUID) error
	// GetUserRoles 获取用户的角色
	GetUserRoles(ctx context.Context, userID util.UUID) ([]string, error)

	// CreateUserGroup 创建用户组
	CreateUserGroup(ctx context.Context, userGroup *models.UserGroup) error
	// UpdateUserGroup 更新用户组
	UpdateUserGroup(ctx context.Context, userGroup *models.UserGroup) error
	// DeleteUserGroup 删除用户组
	DeleteUserGroup(ctx context.Context, groupCode string, operatorId *util.UUID) error
	// GetUserGroupByID 根据用户组ID获取用户组
	GetUserGroupByID(ctx context.Context, groupID []byte) (*models.UserGroup, error)
	// GetUserGroupByCode 根据用户组代码获取用户组
	GetUserGroupByCode(ctx context.Context, groupCode string) (*models.UserGroup, error)
	// GetUserGroupMembers 获取用户组成员
	// 返回成员用户名列表
	GetUserGroupMembers(ctx context.Context, groupCode string) ([]util.UUID, error)
	// GetUserGroupRoles 获取用户组的角色
	GetUserGroupRoles(ctx context.Context, groupCode string) ([]string, error)
	// AssignRoleToUserGroup 分配角色到用户组
	AssignRoleToUserGroup(ctx context.Context, roleCode string, groupCode string, operatorId *util.UUID) error
	// RemoveRoleFromUserGroup 从用户组中移除角色
	RemoveRoleFromUserGroup(ctx context.Context, roleCode string, groupCode string, operatorId *util.UUID) error
	// GetUserGroupPermissions 获取用户组的权限
	GetUserGroupPermissions(ctx context.Context, groupCode string) ([]string, error)

	// AssignUserToGroup 分配用户到用户组
	AssignUserToGroup(ctx context.Context, userID util.UUID, groupCode string, operatorId *util.UUID) error
	// RevokeUserFromGroup 撤销用户组中的用户
	RevokeUserFromGroup(ctx context.Context, userID util.UUID, groupCode string, operatorId *util.UUID) error
	// GetUserGroups 获取用户所属的用户组
	// 返回用户组名称列表
	GetUserGroups(ctx context.Context, userID util.UUID) ([]string, error)

	// GetUserPermissions 获取用户的权限
	// 返回权限代码列表
	GetUserPermissions(ctx context.Context, userID util.UUID) ([]string, error)
	// HasPermission 检查用户是否有特定权限
	HasPermission(ctx context.Context, userID util.UUID, permissionCode string) bool
	// CanAccess 检查用户是否可以以某种方法访问特定资源
	CanAccess(ctx context.Context, userID util.UUID, resource string, method string) bool

	// GetRoleList 获取角色列表
	GetRoleList(ctx context.Context, page uint32, pageSize uint32) ([]*models.Role, error)
	// GetPermissionList 获取权限列表
	GetPermissionList(ctx context.Context, page uint32, pageSize uint32) ([]*models.Permission, error)
	// GetUserGroupList 获取用户组列表
	GetUserGroupList(ctx context.Context, page uint32, pageSize uint32) ([]*models.UserGroup, error)
}

type RepoImpl struct {
	DB      *gorm.DB
	Version int
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &RepoImpl{
		DB:      db,
		Version: 1,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}

func (r *RepoImpl) CreatePermission(ctx context.Context, permission *models.Permission) error {
	if permission == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "permission cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Create(permission).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to create permission: ", err)
	}
	return nil
}

func (r *RepoImpl) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	if permission == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "permission cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Model(&models.Permission{}).Where("id = ? and is_deleted = false", permission.ID).Updates(permission).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update permission: ", err)
	}
	return nil
}

func (r *RepoImpl) DeletePermission(ctx context.Context, permissionCode string, operatorId *util.UUID) error {
	if permissionCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "permission code cannot be empty")
	}

	if err := r.DB.WithContext(ctx).Model(&models.Permission{}).Where("code = ? and is_deleted = false", permissionCode).Update("deleted_at", time.Now()).Update("updated_by", operatorId).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to soft delete permission: ", err)
	}
	return nil
}

func (r *RepoImpl) GetPermissionByID(ctx context.Context, permissionID util.UUID) (*models.Permission, error) {
	if permissionID == (util.UUID{}) {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "permission ID cannot be empty")
	}

	var permission models.Permission
	if err := r.DB.WithContext(ctx).Where("id = ? and is_deleted = false", permissionID).First(&permission).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get permission by ID: ", err)
	}
	return &permission, nil
}

func (r *RepoImpl) GetPermissionByCode(ctx context.Context, permissionCode string) (*models.Permission, error) {
	if permissionCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "permission code cannot be empty")
	}

	var permission models.Permission
	if err := r.DB.WithContext(ctx).Where("code = ? and is_deleted = false", permissionCode).First(&permission).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 记录未找到返回nil
		}
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get permission by code: ", err)
	}
	return &permission, nil
}

func (r *RepoImpl) CreateRole(ctx context.Context, role *models.Role) error {
	if role == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "role cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Create(role).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to create role: ", err)
	}
	return nil
}

func (r *RepoImpl) UpdateRole(ctx context.Context, role *models.Role) error {
	if role == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "role cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Model(&models.Role{}).Where("id = ? and is_deleted = false", role.ID).Updates(role).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update role: ", err)
	}
	return nil
}

func (r *RepoImpl) DeleteRole(ctx context.Context, roleCode string, operatorId *util.UUID) error {
	if roleCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "role code cannot be empty")
	}

	if err := r.DB.WithContext(ctx).Model(&models.Role{}).Where("code = ? and is_deleted = false", roleCode).Update("deleted_at", time.Now()).Update("updated_by", operatorId).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to soft delete role: ", err)
	}
	return nil
}

func (r *RepoImpl) GetRoleByID(ctx context.Context, roleID []byte) (*models.Role, error) {
	if len(roleID) == 0 {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "role ID cannot be empty")
	}

	var role models.Role
	if err := r.DB.WithContext(ctx).Where("id = ? and is_deleted = false", roleID).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 记录未找到返回nil
		}
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get role by ID: ", err)
	}
	return &role, nil
}

func (r *RepoImpl) GetRoleByCode(ctx context.Context, roleCode string) (*models.Role, error) {
	if roleCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "role code cannot be empty")
	}

	var role models.Role
	if err := r.DB.WithContext(ctx).Where("code = ? and is_deleted = false", roleCode).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 记录未找到返回nil
		}
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get role by code: ", err)
	}
	return &role, nil
}

func (r *RepoImpl) GrantPermissionToRole(ctx context.Context, permissionCode string, roleCode string, operatorId *util.UUID) error {
	if permissionCode == "" || roleCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "permission code and role code cannot be empty")
	}

	// 获取权限和角色
	permission, err := r.GetPermissionByCode(ctx, permissionCode)
	if err != nil {
		return err
	}
	if permission == nil {
		return cerrors.NewParamError(http.StatusNotFound, "permission not found")
	}

	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 检查是否已存在关联
	var existing models.RolePermission
	err = r.DB.WithContext(ctx).Where("role_id = ? AND permission_id = ? and is_deleted = false", role.ID, permission.ID).First(&existing).Error
	if err == nil {
		// 如果已存在，更新状态为启用
		existing.Status = 1
		existing.UpdatedBy = operatorId
		if err := r.DB.WithContext(ctx).Save(&existing).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update role permission: ", err)
		}
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to check existing role permission: ", err)
	}

	// 创建新的角色权限关联
	rolePermission := &models.RolePermission{
		RoleID:       role.ID,
		PermissionID: permission.ID,
		Status:       1,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
			Version:   &r.Version,
		},
	}

	if err := r.DB.WithContext(ctx).Create(rolePermission).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to grant permission to role: ", err)
	}
	return nil
}

func (r *RepoImpl) RevokePermissionFromRole(ctx context.Context, permissionCode string, roleCode string, operatorId *util.UUID) error {
	if permissionCode == "" || roleCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "permission code and role code cannot be empty")
	}

	// 获取权限和角色
	permission, err := r.GetPermissionByCode(ctx, permissionCode)
	if err != nil {
		return err
	}
	if permission == nil {
		return cerrors.NewParamError(http.StatusNotFound, "permission not found")
	}

	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 软删除：将状态设置为0
	if err := r.DB.WithContext(ctx).Model(&models.RolePermission{}).
		Where("role_id = ? AND permission_id = ?", role.ID, permission.ID).
		Updates(map[string]interface{}{
			"status":     0,
			"updated_by": operatorId,
		}).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to revoke permission from role: ", err)
	}
	return nil
}

func (r *RepoImpl) GetRolePermission(ctx context.Context, roleCode string) ([]string, error) {
	if roleCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "role code cannot be empty")
	}

	// 查询角色的所有权限（包括递归父权限）
	var permissionIDs []interface{}
	if err := r.DB.WithContext(ctx).Model(&models.Permission{}).
		Select("permission.id").
		Joins("JOIN role_permission ON permission.id = role_permission.permission_id").
		Joins("JOIN roles ON role_permission.role_id = roles.id").
		Where("roles.code = ? AND role_permission.status = 1", roleCode).
		Pluck("permission.id", &permissionIDs).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get role permission ids: ", err)
	}

	// 递归查找所有父权限
	visited := make(map[string]bool)
	var allPermissionCodes []string

	var findParents func(ids []interface{}) error
	findParents = func(ids []interface{}) error {
		if len(ids) == 0 {
			return nil
		}
		var perms []models.Permission
		if err := r.DB.WithContext(ctx).Where("id IN ?", ids).Find(&perms).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to get permissions for recursion: ", err)
		}
		var parentIDs []interface{}
		for _, perm := range perms {
			code := perm.Code
			if !visited[code] {
				visited[code] = true
				allPermissionCodes = append(allPermissionCodes, code)
				if len(perm.ParentID) > 0 {
					parentIDs = append(parentIDs, perm.ParentID)
				}
			}
		}
		return findParents(parentIDs)
	}

	if err := findParents(permissionIDs); err != nil {
		return nil, err
	}
	return allPermissionCodes, nil
}

func (r *RepoImpl) AssignRoleToUser(ctx context.Context, roleCode string, userID util.UUID, operatorId *util.UUID) error {
	if roleCode == "" || userID == (util.UUID{}) {
		return cerrors.NewParamError(http.StatusBadRequest, "role code and userID cannot be empty")
	}

	// 获取角色
	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 检查是否已存在关联
	var existing models.UserRole
	err = r.DB.WithContext(ctx).Where("user_id = ? AND role_id = ? and is_deleted = false", userID, role.ID).First(&existing).Error
	if err == nil {
		// 如果已存在，更新状态为启用
		existing.Status = 1
		existing.UpdatedBy = operatorId
		if err := r.DB.WithContext(ctx).Save(&existing).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update user role: ", err)
		}
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to check existing user role: ", err)
	}

	// 创建新的用户角色关联
	userRole := &models.UserRole{
		UserID: userID,
		RoleID: role.ID,
		Status: 1,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
			Version:   &r.Version,
		},
	}

	if err := r.DB.WithContext(ctx).Create(userRole).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to assign role to user: ", err)
	}
	return nil
}

func (r *RepoImpl) RevokeRoleFromUser(ctx context.Context, roleCode string, userID util.UUID, operatorId *util.UUID) error {
	if roleCode == "" || userID == (util.UUID{}) {
		return cerrors.NewParamError(http.StatusBadRequest, "role code and userID cannot be empty")
	}

	// 获取角色
	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 软删除：将状态设置为0
	if err := r.DB.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND role_id = ?", userID, role.ID).
		Updates(map[string]interface{}{
			"status":     0,
			"updated_by": operatorId,
		}).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to revoke role from user: ", err)
	}
	return nil
}

func (r *RepoImpl) GetUserRoles(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID == (util.UUID{}) {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "userID cannot be empty")
	}

	var roleCodes []string
	if err := r.DB.WithContext(ctx).Model(&models.Role{}).
		Select("roles.code").
		Joins("JOIN user_role ON roles.id = user_role.role_id").
		Where("user_role.user_id = ? AND user_role.status = 1", userID).
		Pluck("roles.code", &roleCodes).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user roles: ", err)
	}
	return roleCodes, nil
}

func (r *RepoImpl) CreateUserGroup(ctx context.Context, userGroup *models.UserGroup) error {
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "user group cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Create(userGroup).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to create user group: ", err)
	}
	return nil
}

func (r *RepoImpl) UpdateUserGroup(ctx context.Context, userGroup *models.UserGroup) error {
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusBadRequest, "user group cannot be nil")
	}

	if err := r.DB.WithContext(ctx).Model(&models.UserGroup{}).Where("id = ? and is_deleted = false", userGroup.ID).Updates(userGroup).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update user group: ", err)
	}
	return nil
}

func (r *RepoImpl) DeleteUserGroup(ctx context.Context, groupCode string, operatorId *util.UUID) error {
	if groupCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "group code cannot be empty")
	}

	// 软删除：设置 deleted_at 字段为当前时间
	if err := r.DB.WithContext(ctx).Model(&models.UserGroup{}).Where("code = ? and is_deleted = false", groupCode).Updates(map[string]interface{}{
		"deleted_at": time.Now(),
		"updated_by": operatorId,
	}).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to delete user group: ", err)
	}

	return nil
}

func (r *RepoImpl) GetUserGroupByID(ctx context.Context, groupID []byte) (*models.UserGroup, error) {
	if len(groupID) == 0 {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "group ID cannot be empty")
	}

	var userGroup models.UserGroup
	if err := r.DB.WithContext(ctx).Where("id = ? and is_deleted = false", groupID).First(&userGroup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 记录未找到返回nil
		}
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group by ID: ", err)
	}
	return &userGroup, nil
}

func (r *RepoImpl) GetUserGroupByCode(ctx context.Context, groupCode string) (*models.UserGroup, error) {
	if groupCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "group code cannot be empty")
	}

	var userGroup models.UserGroup
	if err := r.DB.WithContext(ctx).Where("code = ? and is_deleted = false", groupCode).First(&userGroup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // 记录未找到返回nil
		}
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group by code: ", err)
	}
	return &userGroup, nil
}

func (r *RepoImpl) GetUserGroupMembers(ctx context.Context, groupCode string) ([]util.UUID, error) {
	if groupCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "group code cannot be empty")
	}

	var userIDList []util.UUID
	if err := r.DB.WithContext(ctx).Model(&models.UserGroup{}).
		Select("user_group_relation.user_id").
		Joins("JOIN user_group_relation ON user_group.id = user_group_relation.group_id").
		Where("user_group.code = ? AND user_group_relation.status = 1 AND user_group.is_deleted = false", groupCode).
		Pluck("user_group_relation.user_id", &userIDList).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group members: ", err)
	}
	return userIDList, nil
}

func (r *RepoImpl) AssignRoleToUserGroup(ctx context.Context, roleCode string, groupCode string, operatorId *util.UUID) error {
	if roleCode == "" || groupCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "role code and group code cannot be empty")
	}

	// 获取角色
	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 获取用户组
	userGroup, err := r.GetUserGroupByCode(ctx, groupCode)
	if err != nil {
		return err
	}
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusNotFound, "user group not found")
	}

	// 检查是否已存在关联
	var existing models.RoleGroup
	err = r.DB.WithContext(ctx).Where("role_id = ? AND group_id = ? and is_deleted = false", role.ID, userGroup.ID).First(&existing).Error
	if err == nil {
		// 如果已存在，更新状态为启用
		existing.Status = 1
		existing.UpdatedBy = operatorId
		if err := r.DB.WithContext(ctx).Save(&existing).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update role group: ", err)
		}
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to check existing role group: ", err)
	}

	// 创建新的角色用户组关联
	roleGroup := &models.RoleGroup{
		RoleID:  role.ID,
		GroupID: userGroup.ID,
		Status:  1,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
			Version:   &r.Version,
		},
	}

	if err := r.DB.WithContext(ctx).Create(roleGroup).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to assign role to user group: ", err)
	}
	return nil
}

func (r *RepoImpl) RemoveRoleFromUserGroup(ctx context.Context, roleCode string, groupCode string, operatorId *util.UUID) error {
	if roleCode == "" || groupCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "role code and group name cannot be empty")
	}

	// 获取角色
	role, err := r.GetRoleByCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if role == nil {
		return cerrors.NewParamError(http.StatusNotFound, "role not found")
	}

	// 获取用户组
	userGroup, err := r.GetUserGroupByCode(ctx, groupCode)
	if err != nil {
		return err
	}
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusNotFound, "user group not found")
	}

	// 软删除：将状态设置为0
	if err := r.DB.WithContext(ctx).Model(&models.RoleGroup{}).
		Where("role_id = ? AND group_id = ?", role.ID, userGroup.ID).
		Updates(map[string]interface{}{
			"status":     0,
			"updated_by": operatorId,
		}).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to revoke role from user group: ", err)
	}
	return nil
}

func (r *RepoImpl) GetUserGroupPermissions(ctx context.Context, groupCode string) ([]string, error) {
	if groupCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "group name cannot be empty")
	}

	var permissionCodes []string
	if err := r.DB.WithContext(ctx).Model(&models.Permission{}).
		Select("DISTINCT permission.code").
		Joins("JOIN role_permission ON permission.id = role_permission.permission_id").
		Joins("JOIN role_group ON role_permission.role_id = role_group.role_id").
		Joins("JOIN user_group ON role_group.group_id = user_group.id").
		Where("user_group.code = ? AND role_permission.status = 1 AND role_group.status = 1", groupCode).
		Pluck("permission.code", &permissionCodes).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group permissions: ", err)
	}
	return permissionCodes, nil
}

func (r *RepoImpl) AssignUserToGroup(ctx context.Context, userID util.UUID, groupCode string, operatorId *util.UUID) error {
	if userID == (util.UUID{}) || groupCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "userID and group name cannot be empty")
	}

	// 获取用户组
	userGroup, err := r.GetUserGroupByCode(ctx, groupCode)
	if err != nil {
		return err
	}
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusNotFound, "user group not found")
	}

	// 检查是否已存在关联
	var existing models.UserGroupRelation
	err = r.DB.WithContext(ctx).Where("user_id = ? AND group_id = ? and is_deleted = false", userID, userGroup.ID).First(&existing).Error
	if err == nil {
		// 如果已存在，更新状态为启用
		existing.Status = 1
		existing.UpdatedBy = operatorId
		if err := r.DB.WithContext(ctx).Save(&existing).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to update user group relation: ", err)
		}
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to check existing user group relation: ", err)
	}

	// 创建新的用户组关联
	userGroupRelation := &models.UserGroupRelation{
		UserID:  userID,
		GroupID: userGroup.ID,
		Status:  1,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
			Version:   &r.Version,
		},
	}

	if err := r.DB.WithContext(ctx).Create(userGroupRelation).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to assign user to group: ", err)
	}
	return nil
}

func (r *RepoImpl) RevokeUserFromGroup(ctx context.Context, userID util.UUID, groupCode string, operatorId *util.UUID) error {
	if userID == (util.UUID{}) || groupCode == "" {
		return cerrors.NewParamError(http.StatusBadRequest, "userID and group code cannot be empty")
	}

	// 获取用户组
	userGroup, err := r.GetUserGroupByCode(ctx, groupCode)
	if err != nil {
		return err
	}
	if userGroup == nil {
		return cerrors.NewParamError(http.StatusNotFound, "user group not found")
	}

	// 软删除：将状态设置为0
	if err := r.DB.WithContext(ctx).Model(&models.UserGroupRelation{}).
		Where("user_id = ? AND group_id = ?", userID, userGroup.ID).
		Updates(map[string]interface{}{
			"status":     0,
			"updated_by": operatorId,
		}).Error; err != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "failed to revoke user from group: ", err)
	}
	return nil
}

func (r *RepoImpl) GetUserGroups(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID == (util.UUID{}) {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "userID cannot be empty")
	}

	var groupCodes []string
	if err := r.DB.WithContext(ctx).Model(&models.UserGroup{}).
		Select("user_group.code").
		Joins("JOIN user_group_relation ON user_group.id = user_group_relation.group_id").
		Where("user_group_relation.user_id = ? AND user_group_relation.status = 1", userID).
		Pluck("user_group.code", &groupCodes).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user groups: ", err)
	}
	return groupCodes, nil
}

func (r *RepoImpl) GetUserPermissions(ctx context.Context, userID util.UUID) ([]string, error) {
	if userID == (util.UUID{}) {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "userID cannot be empty")
	}

	var permissionCodes []string

	// 获取用户直接分配的角色权限
	directPermissions, err := r.getUserDirectPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	permissionCodes = append(permissionCodes, directPermissions...)

	// 获取用户通过用户组获得的权限
	groupPermissions, err := r.getUserGroupPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	permissionCodes = append(permissionCodes, groupPermissions...)

	// 去重
	seen := make(map[string]bool)
	var uniquePermissions []string
	for _, perm := range permissionCodes {
		if !seen[perm] {
			seen[perm] = true
			uniquePermissions = append(uniquePermissions, perm)
		}
	}

	return uniquePermissions, nil
}

// getUserDirectPermissions 获取用户通过直接角色分配获得的权限
func (r *RepoImpl) getUserDirectPermissions(ctx context.Context, userID util.UUID) ([]string, error) {
	relos := make([]string, 0)
	if err := r.DB.WithContext(ctx).Model(&models.Role{}).
		Select("roles.code").
		Joins("JOIN user_role ON roles.id = user_role.role_id").
		Where("user_role.user_id = ? AND user_role.status = 1", userID).
		Pluck("roles.code", &relos).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user direct permissions: ", err)
	}
	permissions := make([]string, 0)
	for _, role := range relos {
		perms, err := r.GetRolePermission(ctx, role)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, perms...)
	}
	// 去重
	seen := make(map[string]bool)
	for _, perm := range permissions {
		seen[perm] = true
	}
	var uniquePermissions []string
	for perm := range seen {
		uniquePermissions = append(uniquePermissions, perm)
	}
	return uniquePermissions, nil
}

// getUserGroupPermissions 获取用户通过用户组获得的权限
func (r *RepoImpl) getUserGroupPermissions(ctx context.Context, userID util.UUID) ([]string, error) {
	// 递归查询用户组和父用户组
	var groupIDs []interface{}
	if err := r.DB.WithContext(ctx).Model(&models.UserGroup{}).
		Select("user_group.id").
		Joins("JOIN user_group_relation ON user_group.id = user_group_relation.group_id").
		Where("user_group_relation.user_id = ? AND user_group_relation.status = 1", userID).
		Pluck("user_group.id", &groupIDs).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group ids: ", err)
	}

	visited := make(map[string]bool)
	var allGroupIDs []interface{}

	var findParentGroups func(ids []interface{}) error
	findParentGroups = func(ids []interface{}) error {
		if len(ids) == 0 {
			return nil
		}
		var groups []models.UserGroup
		if err := r.DB.WithContext(ctx).Where("id IN ?", ids).Find(&groups).Error; err != nil {
			return cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user groups for recursion: ", err)
		}
		var parentIDs []interface{}
		for _, group := range groups {
			idStr := group.ID.String()
			if !visited[idStr] {
				visited[idStr] = true
				allGroupIDs = append(allGroupIDs, group.ID)
				if len(group.ParentID) > 0 {
					parentIDs = append(parentIDs, group.ParentID)
				}
			}
		}
		return findParentGroups(parentIDs)
	}

	if err := findParentGroups(groupIDs); err != nil {
		return nil, err
	}

	// 查询所有这些用户组的角色代码
	var roleCodes []string
	if err := r.DB.WithContext(ctx).Model(&models.Role{}).
		Select("roles.code").
		Joins("JOIN role_group ON roles.id = role_group.role_id").
		Where("role_group.group_id IN ? AND role_group.status = 1", allGroupIDs).
		Pluck("roles.code", &roleCodes).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group role codes: ", err)
	}

	// 获取所有角色的权限代码
	var permissions []string
	for _, roleCode := range roleCodes {
		perms, err := r.GetRolePermission(ctx, roleCode)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, perms...)
	}
	// 去重
	seen := make(map[string]bool)
	for _, perm := range permissions {
		seen[perm] = true
	}
	var uniquePermissions []string
	for perm := range seen {
		uniquePermissions = append(uniquePermissions, perm)
	}
	return uniquePermissions, nil
}

func (r *RepoImpl) HasPermission(ctx context.Context, userID util.UUID, permissionCode string) bool {
	if userID == (util.UUID{}) || permissionCode == "" {
		return false
	}

	permissions, err := r.GetUserPermissions(ctx, userID)
	if err != nil {
		return false
	}

	for _, perm := range permissions {
		if perm == permissionCode {
			return true
		}
	}
	return false
}

func (r *RepoImpl) CanAccess(ctx context.Context, userID util.UUID, resource string, method string) bool {
	if userID == (util.UUID{}) || resource == "" || method == "" {
		return false
	}

	// 检查用户是否有对应资源和方法的权限
	var count int64
	err := r.DB.WithContext(ctx).Model(&models.Permission{}).
		Select("COUNT(DISTINCT permission.id)").
		Joins("JOIN role_permission ON permission.id = role_permission.permission_id").
		Joins("JOIN user_role ON role_permission.role_id = user_role.role_id").
		Where("user_role.user_id = ? AND permission.resource = ? AND permission.method = ? AND role_permission.status = 1 AND user_role.status = 1",
			userID, resource, method).
		Count(&count)

	if err.Error != nil {
		return false
	}

	if count > 0 {
		return true
	}

	// 检查用户是否通过用户组有对应资源和方法的权限
	err = r.DB.WithContext(ctx).Model(&models.Permission{}).
		Select("COUNT(DISTINCT permission.id)").
		Joins("JOIN role_permission ON permission.id = role_permission.permission_id").
		Joins("JOIN role_group ON role_permission.role_id = role_group.role_id").
		Joins("JOIN user_group_relation ON role_group.group_id = user_group_relation.group_id").
		Where("user_group_relation.user_id = ? AND permission.resource = ? AND permission.method = ? AND role_permission.status = 1 AND role_group.status = 1 AND user_group_relation.status = 1",
			userID, resource, method).
		Count(&count)

	if err.Error != nil {
		return false
	}

	return count > 0
}

func (r *RepoImpl) GetRoleList(ctx context.Context, page uint32, pageSize uint32) ([]*models.Role, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 || pageSize > 100 {
		pageSize = 10
	}

	var roles []*models.Role
	offset := (page - 1) * pageSize

	if err := r.DB.WithContext(ctx).Offset(int(offset)).Limit(int(pageSize)).Find(&roles).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get role list: ", err)
	}
	return roles, nil
}

func (r *RepoImpl) GetPermissionList(ctx context.Context, page uint32, pageSize uint32) ([]*models.Permission, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 || pageSize > 100 {
		pageSize = 10
	}

	var permissions []*models.Permission
	offset := (page - 1) * pageSize

	if err := r.DB.WithContext(ctx).Offset(int(offset)).Limit(int(pageSize)).Find(&permissions).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get permission list: ", err)
	}
	return permissions, nil
}

func (r *RepoImpl) GetUserGroupList(ctx context.Context, page uint32, pageSize uint32) ([]*models.UserGroup, error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 || pageSize > 100 {
		pageSize = 10
	}

	var userGroups []*models.UserGroup
	offset := (page - 1) * pageSize

	if err := r.DB.WithContext(ctx).Offset(int(offset)).Limit(int(pageSize)).Find(&userGroups).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group list: ", err)
	}
	return userGroups, nil
}

func (r *RepoImpl) GetUserGroupRoles(ctx context.Context, groupCode string) ([]string, error) {
	if groupCode == "" {
		return nil, cerrors.NewParamError(http.StatusBadRequest, "group code cannot be empty")
	}

	var roleCodes []string
	if err := r.DB.WithContext(ctx).Model(&models.Role{}).
		Select("roles.code").
		Joins("JOIN role_group ON roles.id = role_group.role_id").
		Joins("JOIN user_group ON role_group.group_id = user_group.id").
		Where("user_group.code = ? AND role_group.status = 1 AND user_group.is_deleted = false", groupCode).
		Pluck("roles.code", &roleCodes).Error; err != nil {
		return nil, cerrors.NewSQLError(http.StatusInternalServerError, "failed to get user group roles: ", err)
	}
	return roleCodes, nil
}
