package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/123508/xservergo/apps/auth/service"
	auth "github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
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
		return models.PermissionTypeAPI
	}
}

func getUUIDFromBytes(b []byte) (*util.UUID, error) {
	if len(b) == 0 {
		return nil, nil
	}
	uid := &util.UUID{}
	if err := uid.Unmarshal(b); err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	return uid, nil
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
	parentId := &util.UUID{}
	if err := parentId.Unmarshal(req.Permission.ParentId); err != nil {
		parentId = nil
	}
	operatorId, err := getUUIDFromBytes(req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	status := int8(1)
	if !req.Permission.Status {
		status = 0
	}
	permission := models.Permission{
		ID:          util.NewUUID(),
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
	id, err := newPermission.ID.Marshal()
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化权限ID失败")
	}
	var parentIdMarshaled []byte
	if newPermission.ParentID != nil {
		parentIdMarshaled, err = newPermission.ParentID.Marshal()
		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化父级ID失败")
		}
	}
	return &auth.Permission{
		Id:             id,
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
	parentId := &util.UUID{}
	if err := parentId.Unmarshal(req.Permission.ParentId); err != nil {
		parentId = nil
	}
	operatorId, err := getUUIDFromBytes(req.RequestUserId)
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}
	status := int8(1)
	if !req.Permission.Status {
		status = 0
	}
	permissionId := util.UUID{}
	if err := permissionId.Unmarshal(req.Permission.Id); err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
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
	id, err := newPermission.ID.Marshal()
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化权限ID失败")
	}
	var parentIdMarshaled []byte
	if newPermission.ParentID != nil {
		parentIdMarshaled, err = newPermission.ParentID.Marshal()
		if err != nil {
			return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化父级ID失败")
		}
	}
	return &auth.Permission{
		Id:             id,
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
	operatorId, err := getUUIDFromBytes(req.RequestUserId)
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
	id, err := permission.ID.Marshal()
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化权限ID失败")
	}
	parentIdMarshaled, err := permission.ParentID.Marshal()
	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化父级ID失败")
	}
	return &auth.Permission{
		Id:             id,
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
	// TODO: Your code here...
	return
}

// UpdateRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdateRole(ctx context.Context, req *auth.UpdateRoleReq) (resp *auth.Role, err error) {
	// TODO: Your code here...
	return
}

// DeleteRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeleteRole(ctx context.Context, req *auth.DeleteRoleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetRole(ctx context.Context, req *auth.GetRoleReq) (resp *auth.Role, err error) {
	// TODO: Your code here...
	return
}

// GrantPermissionToRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GrantPermissionToRole(ctx context.Context, req *auth.GrantPermissionToRoleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// RevokePermissionFromRole implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RevokePermissionFromRole(ctx context.Context, req *auth.RevokePermissionFromRoleReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetRolePermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetRolePermissions(ctx context.Context, req *auth.GetRolePermissionsReq) (resp *auth.GetRolePermissionsResp, err error) {
	// TODO: Your code here...
	return
}

// AssignRoleToUser implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignRoleToUser(ctx context.Context, req *auth.AssignRoleToUserReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// RemoveRoleFromUser implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveRoleFromUser(ctx context.Context, req *auth.RemoveRoleFromUserReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetUserRoles implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserRoles(ctx context.Context, req *auth.GetUserRolesReq) (resp *auth.GetUserRolesResp, err error) {
	// TODO: Your code here...
	return
}

// CreateUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CreateUserGroup(ctx context.Context, req *auth.CreateUserGroupReq) (resp *auth.UserGroup, err error) {
	// TODO: Your code here...
	return
}

// UpdateUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) UpdateUserGroup(ctx context.Context, req *auth.UpdateUserGroupReq) (resp *auth.UserGroup, err error) {
	// TODO: Your code here...
	return
}

// DeleteUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) DeleteUserGroup(ctx context.Context, req *auth.DeleteUserGroupReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroup(ctx context.Context, req *auth.GetUserGroupReq) (resp *auth.UserGroup, err error) {
	// TODO: Your code here...
	return
}

// GetUserGroupMembers implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroupMembers(ctx context.Context, req *auth.GetUserGroupMembersReq) (resp *auth.GetUserGroupMembersResp, err error) {
	// TODO: Your code here...
	return
}

// GetUserGroupPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroupPermissions(ctx context.Context, req *auth.GetUserGroupPermissionsReq) (resp *auth.GetUserGroupPermissionsResp, err error) {
	// TODO: Your code here...
	return
}

// AssignUserToGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignUserToGroup(ctx context.Context, req *auth.AssignUserToGroupReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// RemoveUserFromGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveUserFromGroup(ctx context.Context, req *auth.RemoveUserFromGroupReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// GetUserGroups implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserGroups(ctx context.Context, req *auth.GetUserGroupsReq) (resp *auth.GetUserGroupsResp, err error) {
	// TODO: Your code here...
	return
}

// GetUserPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) GetUserPermissions(ctx context.Context, req *auth.GetUserPermissionsReq) (resp *auth.GetUserPermissionsResp, err error) {
	// TODO: Your code here...
	return
}

// HasPermission implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) HasPermission(ctx context.Context, req *auth.HasPermissionReq) (resp *auth.HasPermissionResp, err error) {
	// TODO: Your code here...
	return
}

// CanAccess implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) CanAccess(ctx context.Context, req *auth.CanAccessReq) (resp *auth.CanAccessResp, err error) {
	// TODO: Your code here...
	return
}

// ListRoles implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListRoles(ctx context.Context, req *auth.ListRolesReq) (resp *auth.ListRolesResp, err error) {
	// TODO: Your code here...
	return
}

// ListUserGroups implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListUserGroups(ctx context.Context, req *auth.ListUserGroupsReq) (resp *auth.ListUserGroupsResp, err error) {
	// TODO: Your code here...
	return
}

// ListPermissions implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) ListPermissions(ctx context.Context, req *auth.ListPermissionsReq) (resp *auth.ListPermissionsResp, err error) {
	// TODO: Your code here...
	return
}

// IssueToken implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) IssueToken(ctx context.Context, req *auth.IssueTokenReq) (resp *auth.IssueTokenResp, err error) {

	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	token, err := s.authService.IssueToken(ctx, uid)

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
	uid := util.NewUUID()

	if err = uid.Unmarshal(req.UserId); err != nil {
		return nil, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误")
	}

	token := models.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
	}

	Token, err := s.authService.RefreshToken(ctx, token, uid)

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}

	return &auth.RefreshTokenResp{
		AccessToken:  Token.AccessToken,
		RefreshToken: Token.RefreshToken,
	}, nil
}

// VerifyToken implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) VerifyToken(ctx context.Context, req *auth.VerifyTokenReq) (resp *auth.VerifyTokenResp, err error) {
	uid, perms, ver, err := s.authService.VerifyToken(ctx, req.AccessToken)

	if err != nil {
		if com, ok := err.(*cerrors.CommonError); ok {
			return nil, cerrors.NewGRPCError(com.Code, com.Message)
		}
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "服务器异常")
	}

	Uid, err := uid.Marshal()

	if err != nil {
		return nil, cerrors.NewGRPCError(http.StatusInternalServerError, "序列化失败")
	}

	return &auth.VerifyTokenResp{
		UserId:      Uid,
		Permissions: perms,
		Version:     ver,
	}, nil
}

// AssignRoleToUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) AssignRoleToUserGroup(ctx context.Context, req *auth.AssignRoleToUserGroupReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}

// RemoveRoleFromUserGroup implements the AuthServiceImpl interface.
func (s *AuthServiceImpl) RemoveRoleFromUserGroup(ctx context.Context, req *auth.RemoveRoleFromUserGroupReq) (resp *auth.OperationResult, err error) {
	// TODO: Your code here...
	return
}
