package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/123508/xservergo/pkg/util/id"

	"github.com/123508/xservergo/apps/auth/service"
	auth "github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// permissionTypeFromString maps string to auth.Permission_Type enum.
func permissionTypeFromString(t string) auth.Permission_Type {
	switch t {
	case "MENU":
		return auth.Permission_MENU
	case "BUTTON":
		return auth.Permission_BUTTON
	case "API":
		return auth.Permission_API
	case "DATA":
		return auth.Permission_DATA
	case "FILE":
		return auth.Permission_FILE
	case "FIELD":
		return auth.Permission_FIELD
	case "TASK":
		return auth.Permission_TASK
	case "MODULE":
		return auth.Permission_MODULE
	default:
		return auth.Permission_API
	}
}

func permissionTypeFromInt(t auth.Permission_Type) models.PermissionType {
	switch t {
	case auth.Permission_API:
		return models.PermissionTypeAPI
	case auth.Permission_MENU:
		return models.PermissionTypeMenu
	case auth.Permission_BUTTON:
		return models.PermissionTypeButton
	case auth.Permission_DATA:
		return models.PermissionTypeData
	case auth.Permission_FILE:
		return models.PermissionTypeFile
	case auth.Permission_FIELD:
		return models.PermissionTypeField
	case auth.Permission_TASK:
		return models.PermissionTypeTask
	case auth.Permission_MODULE:
		return models.PermissionTypeModule
	default:
		return ""
	}
}

func unmarshalParentUID(ctx context.Context, uid string) (*id.UUID, error) {
	if uid == "" || len(uid) == 0 {
		return nil, nil
	}

	Uid := id.NewUUID()
	if err := Uid.UnmarshalBase64(uid); err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	return &Uid, nil
}

func unmarshalRequestUID(ctx context.Context, uid string) (*id.UUID, error) {

	if uid == "" || len(uid) == 0 {
		return &id.SystemUUID, nil
	}

	Uid := id.NewUUID()
	if err := Uid.UnmarshalBase64(uid); err != nil {
		return &id.SystemUUID, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	return &Uid, nil
}

func marshalUID(ctx context.Context, uid *id.UUID) string {

	if uid == nil {
		return ""
	}

	return (*uid).MarshalBase64()
}

// AuthServiceImpl implements the last service interface defined in the IDL.
type AuthServiceImpl struct {
	authService service.AuthService
}

func NewAuthServiceImpl(database *gorm.DB, rds *redis.Client) *AuthServiceImpl {
	return &AuthServiceImpl{
		authService: service.NewService(database, rds),
	}
}

// CreatePermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreatePermission(ctx context.Context, req *auth.CreatePermissionReq) (resp *auth.Permission, err error) {

	parentId, err := unmarshalParentUID(ctx, req.Permission.ParentId)

	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	status := int8(1)
	if !req.Permission.Status {
		status = 0
	}

	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)

	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	permission := models.Permission{
		ID:          id.NewUUID(),
		Code:        req.Permission.Code,
		Name:        req.Permission.PermissionName,
		Description: req.Permission.Description,
		ParentID:    parentId,
		Type:        permissionTypeFromInt(req.Permission.Type),
		Resource:    req.Permission.Resource,
		Method:      req.Permission.Method,
		Status:      status,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
		},
	}
	newPermission, err := s.authService.CreatePermission(ctx, &permission, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
	}
	uid := marshalUID(ctx, &newPermission.ID)
	var parentIdMarshaled string

	if newPermission.ParentID != nil {
		parentIdMarshaled = newPermission.ParentID.MarshalBase64()
	}
	return &auth.Permission{
		Id:             uid,
		Code:           newPermission.Code,
		PermissionName: newPermission.Name,
		Description:    newPermission.Description,
		ParentId:       parentIdMarshaled,
		Type:           permissionTypeFromString(string(newPermission.Type)),
		Resource:       newPermission.Resource,
		Method:         newPermission.Method,
		Status:         newPermission.Status == 1,
	}, nil
}

// UpdatePermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdatePermission(ctx context.Context, req *auth.UpdatePermissionReq) (resp *auth.Permission, err error) {
	parentId, err := unmarshalParentUID(ctx, req.Permission.ParentId)

	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	status := int8(1)
	if !req.Permission.Status {
		status = 0
	}
	permissionId := id.UUID{}
	if req.Permission.Id != "" {
		if err := permissionId.UnmarshalBase64(req.Permission.Id); err != nil {
			return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
		}
	}
	permission := models.Permission{
		ID:          permissionId,
		Code:        req.Permission.Code,
		Name:        req.Permission.PermissionName,
		Description: req.Permission.Description,
		ParentID:    parentId,
		Type:        permissionTypeFromInt(req.Permission.Type),
		Resource:    req.Permission.Resource,
		Method:      req.Permission.Method,
		Status:      status,
		AuditFields: models.AuditFields{
			UpdatedBy: operatorId,
		},
	}
	newPermission, err := s.authService.UpdatePermission(ctx, &permission, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
	}
	var parentIdMarshaled string
	if newPermission.ParentID != nil {
		parentIdMarshaled = newPermission.ParentID.MarshalBase64()
	}
	return &auth.Permission{
		Id:             newPermission.ID.MarshalBase64(),
		Code:           newPermission.Code,
		PermissionName: newPermission.Name,
		Description:    newPermission.Description,
		ParentId:       parentIdMarshaled,
		Type:           permissionTypeFromString(string(newPermission.Type)),
		Resource:       newPermission.Resource,
		Method:         newPermission.Method,
		Status:         newPermission.Status == 1,
	}, nil
}

// DeletePermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeletePermission(ctx context.Context, req *auth.DeletePermissionReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.DeletePermission(ctx, req.PermissionCode, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetPermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetPermission(ctx context.Context, req *auth.GetPermissionReq) (resp *auth.Permission, err error) {
	permission, err := s.authService.GetPermissionByCode(ctx, req.PermissionCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusNotFound, "权限不存在")
	}
	uid := marshalUID(ctx, &permission.ID)
	parentIdMarshaled := marshalUID(ctx, permission.ParentID)
	return &auth.Permission{
		Id:             uid,
		Code:           permission.Code,
		PermissionName: permission.Name,
		Description:    permission.Description,
		ParentId:       parentIdMarshaled,
		Type:           permissionTypeFromString(string(permission.Type)),
		Resource:       permission.Resource,
		Method:         permission.Method,
		Status:         permission.Status == 1,
	}, nil
}

// CreateRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreateRole(ctx context.Context, req *auth.CreateRoleReq) (resp *auth.Role, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	role := models.Role{
		ID:          id.NewUUID(),
		Code:        req.Role.Code,
		Name:        req.Role.RoleName,
		Description: req.Role.Description,
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
		},
	}
	newRole, err := s.authService.CreateRole(ctx, &role, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	uid := marshalUID(ctx, &newRole.ID)
	return &auth.Role{
		Id:          uid,
		Code:        newRole.Code,
		RoleName:    newRole.Name,
		Description: newRole.Description,
	}, nil
}

// UpdateRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdateRole(ctx context.Context, req *auth.UpdateRoleReq) (resp *auth.Role, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	role := models.Role{
		Code:        req.Role.Code,
		Name:        req.Role.RoleName,
		Description: req.Role.Description,
		AuditFields: models.AuditFields{
			UpdatedBy: operatorId,
		},
	}
	updatedRole, err := s.authService.UpdateRole(ctx, &role, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	uid := marshalUID(ctx, &updatedRole.ID)
	return &auth.Role{
		Id:          uid,
		Code:        updatedRole.Code,
		RoleName:    updatedRole.Name,
		Description: updatedRole.Description,
	}, nil
}

// DeleteRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeleteRole(ctx context.Context, req *auth.DeleteRoleReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.DeleteRole(ctx, req.RoleCode, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetRole(ctx context.Context, req *auth.GetRoleReq) (resp *auth.Role, err error) {
	role, err := s.authService.GetRoleByCode(ctx, req.RoleCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusNotFound, "角色不存在")
	}
	uid := marshalUID(ctx, &role.ID)
	return &auth.Role{
		Id:          uid,
		Code:        role.Code,
		RoleName:    role.Name,
		Description: role.Description,
	}, nil
}

// GrantPermissionToRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GrantPermissionToRole(ctx context.Context, req *auth.GrantPermissionToRoleReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.GrantPermissionToRole(ctx, req.PermissionCode, req.RoleCode, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// RevokePermissionFromRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RevokePermissionFromRole(ctx context.Context, req *auth.RevokePermissionFromRoleReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.RevokePermissionFromRole(ctx, req.PermissionCode, req.RoleCode, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetRolePermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetRolePermissions(ctx context.Context, req *auth.GetRolePermissionsReq) (resp *auth.GetRolePermissionsResp, err error) {
	permissions, err := s.authService.GetRolePermissions(ctx, req.RoleCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取角色权限失败")
	}
	var authPermissions []*auth.Permission
	for _, p := range permissions {
		authPermissions = append(authPermissions, &auth.Permission{Code: p})
	}
	return &auth.GetRolePermissionsResp{
		Permissions: authPermissions,
	}, nil
}

// AssignRoleToUser implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignRoleToUser(ctx context.Context, req *auth.AssignRoleToUserReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	userId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.AssignRoleToUser(ctx, req.GetRoleCode(), *userId, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// RemoveRoleFromUser implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveRoleFromUser(ctx context.Context, req *auth.RemoveRoleFromUserReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	userId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.RevokeRoleFromUser(ctx, req.GetRoleCode(), *userId, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetUserRoles implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserRoles(ctx context.Context, req *auth.GetUserRolesReq) (resp *auth.GetUserRolesResp, err error) {
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	roles, err := s.authService.GetUserRoles(ctx, *targetUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户角色失败")
	}
	var authRoles []*auth.Role
	for _, roleCode := range roles {
		authRoles = append(authRoles, &auth.Role{Code: roleCode})
	}
	return &auth.GetUserRolesResp{
		Roles: authRoles,
	}, nil
}

// CreateUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreateUserGroup(ctx context.Context, req *auth.CreateUserGroupReq) (resp *auth.UserGroup, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	userGroup := models.UserGroup{
		ID:   id.NewUUID(),
		Code: req.GetUserGroup().GetCode(),
		Name: req.GetUserGroup().GetGroupName(),
		AuditFields: models.AuditFields{
			CreatedBy: operatorId,
		},
	}
	newUserGroup, err := s.authService.CreateUserGroup(ctx, &userGroup, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	uid := marshalUID(ctx, &newUserGroup.ID)
	return &auth.UserGroup{
		Id:        uid,
		GroupName: newUserGroup.Name,
	}, nil
}

// UpdateUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdateUserGroup(ctx context.Context, req *auth.UpdateUserGroupReq) (resp *auth.UserGroup, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	userGroup := models.UserGroup{
		Code: req.UserGroup.Code,
		Name: req.UserGroup.GroupName,
	}
	updatedUserGroup, err := s.authService.UpdateUserGroup(ctx, &userGroup, operatorId)
	if err != nil {
		var com *cerrors.CommonError
		if errors.As(err, &com) {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}
	uid := marshalUID(ctx, &updatedUserGroup.ID)
	return &auth.UserGroup{
		Id:        uid,
		Code:      updatedUserGroup.Code,
		GroupName: updatedUserGroup.Name,
	}, nil
}

// DeleteUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeleteUserGroup(ctx context.Context, req *auth.DeleteUserGroupReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.DeleteUserGroup(ctx, req.UserGroupCode, operatorId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "删除用户组失败")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroup(ctx context.Context, req *auth.GetUserGroupReq) (resp *auth.UserGroup, err error) {
	userGroup, err := s.authService.GetUserGroupByCode(ctx, req.UserGroupCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组失败")
	}
	uid := marshalUID(ctx, &userGroup.ID)
	return &auth.UserGroup{
		Id:        uid,
		Code:      req.UserGroupCode,
		GroupName: userGroup.Name,
	}, nil
}

// GetUserGroupMembers implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroupMembers(ctx context.Context, req *auth.GetUserGroupMembersReq) (resp *auth.GetUserGroupMembersResp, err error) {
	members, err := s.authService.GetUserGroupMembers(ctx, req.UserGroupCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组成员失败")
	}
	var users []*auth.UserInfo
	for _, member := range members {
		idBytes := marshalUID(ctx, &member)
		users = append(users, &auth.UserInfo{
			UserId: idBytes,
		})
	}
	return &auth.GetUserGroupMembersResp{
		Users:      users,
		TotalCount: uint32(len(users)),
	}, nil
}

// GetUserGroupPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroupPermissions(ctx context.Context, req *auth.GetUserGroupPermissionsReq) (resp *auth.GetUserGroupPermissionsResp, err error) {
	permissions, err := s.authService.GetUserGroupPermissions(ctx, req.UserGroupCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组权限失败")
	}
	var authPermissions []*auth.Permission
	for _, p := range permissions {
		authPermissions = append(authPermissions, &auth.Permission{Code: p})
	}
	return &auth.GetUserGroupPermissionsResp{
		Permissions: authPermissions,
	}, nil
}

// AssignUserToGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignUserToGroup(ctx context.Context, req *auth.AssignUserToGroupReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.GetRequestUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "目标用户ID解析失败")
	}
	err = s.authService.AssignUserToGroup(ctx, *targetUserId, req.UserGroupCode, operatorId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "分配用户到组失败")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// RemoveUserFromGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveUserFromGroup(ctx context.Context, req *auth.RemoveUserFromGroupReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.GetRequestUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "目标用户ID解析失败")
	}
	err = s.authService.RevokeUserFromGroup(ctx, *targetUserId, req.UserGroupCode, operatorId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "从组中移除用户失败")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetUserGroups implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroups(ctx context.Context, req *auth.GetUserGroupsReq) (resp *auth.GetUserGroupsResp, err error) {
	targetUserId, err := unmarshalRequestUID(ctx, req.TargetUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "目标用户ID解析失败")
	}
	groups, err := s.authService.GetUserGroups(ctx, *targetUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组失败")
	}
	var authGroups []*auth.UserGroup
	for _, group := range groups {
		authGroups = append(authGroups, &auth.UserGroup{Code: group})
	}
	return &auth.GetUserGroupsResp{
		UserGroups: authGroups,
	}, nil
}

// GetUserPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserPermissions(ctx context.Context, req *auth.GetUserPermissionsReq) (resp *auth.GetUserPermissionsResp, err error) {
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	permissions, err := s.authService.GetUserPermissions(ctx, *targetUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户权限失败")
	}
	var authPermissions []*auth.Permission
	for _, p := range permissions {
		authPermissions = append(authPermissions, &auth.Permission{Code: p})
	}
	return &auth.GetUserPermissionsResp{
		Permissions: authPermissions,
	}, nil
}

// HasPermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) HasPermission(ctx context.Context, req *auth.HasPermissionReq) (resp *auth.HasPermissionResp, err error) {
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	hasPermission := s.authService.HasPermission(ctx, *targetUserId, req.GetPermissionCode())
	return &auth.HasPermissionResp{
		Ok: hasPermission,
	}, nil
}

// CanAccess implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CanAccess(ctx context.Context, req *auth.CanAccessReq) (resp *auth.CanAccessResp, err error) {
	targetUserId, err := unmarshalRequestUID(ctx, req.GetTargetUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	canAccess := s.authService.CanAccess(ctx, *targetUserId, req.GetResource(), req.GetMethod())
	return &auth.CanAccessResp{
		Ok: canAccess,
	}, nil
}

// ListRoles implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListRoles(ctx context.Context, req *auth.ListRolesReq) (resp *auth.ListRolesResp, err error) {
	roles, err := s.authService.GetRoleList(ctx, req.Page, req.PageSize)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取角色列表失败")
	}

	var authRoles []*auth.Role
	for _, role := range roles {
		uid := marshalUID(ctx, &role.ID)
		authRoles = append(authRoles, &auth.Role{
			Id:          uid,
			Code:        role.Code,
			RoleName:    role.Name,
			Description: role.Description,
			Status:      role.Status == 1,
		})
	}

	return &auth.ListRolesResp{
		Roles: authRoles,
	}, nil
}

// ListUserGroups implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListUserGroups(ctx context.Context, req *auth.ListUserGroupsReq) (resp *auth.ListUserGroupsResp, err error) {
	userGroups, err := s.authService.GetUserGroupList(ctx, req.Page, req.PageSize)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组失败")
	}

	var authUserGroups []*auth.UserGroup
	for _, group := range userGroups {
		uid := marshalUID(ctx, &group.ID)
		parentId := ""
		if group.ParentID != nil {
			parentId = group.ParentID.MarshalBase64()
		}
		authUserGroups = append(authUserGroups, &auth.UserGroup{
			Id:        uid,
			Code:      group.Code,
			GroupName: group.Name,
			Status:    group.Status == 1,
			ParentId:  parentId,
		})
	}

	return &auth.ListUserGroupsResp{
		UserGroups: authUserGroups,
	}, nil
}

// ListPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListPermissions(ctx context.Context, req *auth.ListPermissionsReq) (resp *auth.ListPermissionsResp, err error) {
	permissions, err := s.authService.GetPermissionList(ctx, req.Page, req.PageSize)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取权限列表失败")
	}

	var authPermissions []*auth.Permission
	for _, perm := range permissions {
		uid := marshalUID(ctx, &perm.ID)
		parentId := ""
		if perm.ParentID != nil {
			parentId = perm.ParentID.MarshalBase64()
		}
		authPermissions = append(authPermissions, &auth.Permission{
			Id:             uid,
			Code:           perm.Code,
			PermissionName: perm.Name,
			Description:    perm.Description,
			ParentId:       parentId,
			Type:           permissionTypeFromString(string(perm.Type)),
			Resource:       perm.Resource,
			Method:         perm.Method,
			Status:         perm.Status == 1,
		})
	}

	return &auth.ListPermissionsResp{
		Perms: authPermissions,
	}, nil
}

// IssueToken implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) IssueToken(ctx context.Context, req *auth.IssueTokenReq) (resp *auth.IssueTokenResp, err error) {

	uid, err := unmarshalRequestUID(ctx, req.UserId)

	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	token, err := s.authService.IssueToken(ctx, *uid)

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}

	return &auth.IssueTokenResp{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}, nil
}

// RefreshToken implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RefreshToken(ctx context.Context, req *auth.RefreshTokenReq) (resp *auth.RefreshTokenResp, err error) {

	Token, uid, perms, version, ttl, err := s.authService.RefreshToken(ctx, req.RefreshToken)

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}

	return &auth.RefreshTokenResp{
		AccessToken:  Token.AccessToken,
		RefreshToken: Token.RefreshToken,
		UserId:       uid.MarshalBase64(),
		Permissions:  perms,
		Version:      version,
		Ttl:          ttl,
	}, nil
}

// VerifyToken implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) VerifyToken(ctx context.Context, req *auth.VerifyTokenReq) (resp *auth.VerifyTokenResp, err error) {
	uid, perms, ver, ttl, err := s.authService.VerifyToken(ctx, req.AccessToken)

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}

	Uid := marshalUID(ctx, &uid)

	return &auth.VerifyTokenResp{
		UserId:      Uid,
		Permissions: perms,
		Version:     ver,
		Ttl:         ttl,
	}, nil
}

// AssignRoleToUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignRoleToUserGroup(ctx context.Context, req *auth.AssignRoleToUserGroupReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.GetRequestUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.AssignRoleToUserGroup(ctx, req.GetRoleCode(), req.UserGroupCode, operatorId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "分配角色到用户组失败")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// RemoveRoleFromUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveRoleFromUserGroup(ctx context.Context, req *auth.RemoveRoleFromUserGroupReq) (resp *auth.OperationResult, err error) {
	operatorId, err := unmarshalRequestUID(ctx, req.GetRequestUserId())
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	err = s.authService.RemoveRoleFromUserGroup(ctx, req.GetRoleCode(), req.UserGroupCode, operatorId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "从用户组移除角色失败")
	}
	return &auth.OperationResult{
		Success: true,
	}, nil
}

// GetUserGroupRoles implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroupRoles(ctx context.Context, req *auth.GetUserGroupRolesReq) (resp *auth.GetUserGroupRolesResp, err error) {
	roles, err := s.authService.GetUserGroupRoles(ctx, req.UserGroupCode)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "获取用户组角色失败")
	}
	var authRoles []*auth.Role
	for _, roleCode := range roles {
		authRoles = append(authRoles, &auth.Role{Code: roleCode})
	}
	return &auth.GetUserGroupRolesResp{
		Roles: authRoles,
	}, nil
}

// CreatePolicy implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreatePolicy(ctx context.Context, req *auth.CreatePolicyReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// UpdatePolicy implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdatePolicy(ctx context.Context, req *auth.UpdatePolicyReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// DeletePolicy implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeletePolicy(ctx context.Context, req *auth.DeletePolicyReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetPolicy implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetPolicy(ctx context.Context, req *auth.GetPolicyReq) (resp *auth.GetPolicyResp, err error) {
	// TODO: Your code here...
	return
}

// ListPolicies implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListPolicies(ctx context.Context, req *auth.ListPoliciesReq) (resp *auth.ListPoliciesResp, err error) {
	// TODO: Your code here...
	return
}

// CreatePolicyRule implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreatePolicyRule(ctx context.Context, req *auth.CreatePolicyRuleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// UpdatePolicyRule implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdatePolicyRule(ctx context.Context, req *auth.UpdatePolicyRuleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// DeletePolicyRule implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeletePolicyRule(ctx context.Context, req *auth.DeletePolicyRuleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetPolicyRule implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetPolicyRule(ctx context.Context, req *auth.GetPolicyRuleReq) (resp *auth.GetPolicyRuleResp, err error) {
	// TODO: Your code here...
	return
}

// ListPolicyRules implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListPolicyRules(ctx context.Context, req *auth.ListPolicyRulesReq) (resp *auth.ListPolicyRulesResp, err error) {
	// TODO: Your code here...
	return
}

// GetPermissionPolicies implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetPermissionPolicies(ctx context.Context, req *auth.GetPermissionPoliciesReq) (resp *auth.GetPermissionPoliciesResp, err error) {
	// TODO: Your code here...
	return
}

// AttachPolicyToPermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AttachPolicyToPermission(ctx context.Context, req *auth.AttachPolicyToPermissionReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// DetachPolicyFromPermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DetachPolicyFromPermission(ctx context.Context, req *auth.DetachPolicyFromPermissionReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}
