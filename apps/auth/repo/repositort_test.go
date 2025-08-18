package repo

import (
	"context"
	"github.com/123508/xservergo/pkg/util/id"
	"testing"
	"time"

	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/models"
)

var testRepo AuthRepository
var testUserId, _ = id.FromString("01983738-ba08-73f7-97a4-9c9972075337")
var timeNow = time.Now()
var version = 1

func setupTestDB(t *testing.T) AuthRepository {
	if testRepo != nil {
		return testRepo
	}

	d, err := db.InitMySQLDB()
	if err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	testRepo = NewAuthRepository(d)
	return testRepo
}

func TestCreatePermission(t *testing.T) {
	repo := setupTestDB(t)
	uid := id.NewUUID()
	parentId := id.NewUUID()
	permission := &models.Permission{
		ID:          parentId,
		Code:        "test_permission_create",
		Name:        "Test Permission Create",
		Description: "Permission for testing create purposes",
		ParentID:    nil,
		Type:        models.PermissionTypeAPI,
		Resource:    "/test/resource/create",
		Method:      "POST",
		Status:      1,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			UpdatedAt: &timeNow,
			DeletedAt: nil,
			Version:   &version,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}
	err := repo.CreatePermission(context.Background(), permission)
	if err != nil {
		t.Errorf("failed to create permission: %v", err)
	} else {
		t.Logf("permission created successfully: %+v", permission)
	}

	childPermission := &models.Permission{
		ID:          id.NewUUID(),
		Code:        "test_permission_create_child",
		Name:        "Test Permission Create Child",
		Description: "Permission for testing create child purposes",
		ParentID:    &parentId,
		Type:        models.PermissionTypeAPI,
		Resource:    "/test/resource/create/child",
		Method:      "POST",
		Status:      1,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			UpdatedAt: &timeNow,
			DeletedAt: nil,
			Version:   &version,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}
	err = repo.CreatePermission(context.Background(), childPermission)
	if err != nil {
		t.Errorf("failed to create child permission: %v", err)
	} else {
		t.Logf("child permission created successfully: %+v", childPermission)
	}
}

func TestUpdatePermission(t *testing.T) {
	repo := setupTestDB(t)
	uid := id.NewUUID()

	// 先创建一个权限
	permission := &models.Permission{
		ID:          id.NewUUID(),
		Code:        "test_permission_update",
		Name:        "Test Permission Update",
		Description: "Permission for testing update purposes",
		ParentID:    nil,
		Type:        models.PermissionTypeAPI,
		Resource:    "/test/resource/update",
		Method:      "PUT",
		Status:      1,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			UpdatedAt: &timeNow,
			DeletedAt: nil,
			Version:   &version,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}

	err := repo.CreatePermission(context.Background(), permission)
	if err != nil {
		t.Fatalf("failed to create permission for update test: %v", err)
	}

	// 更新权限
	permission.Name = "Updated Test Permission"
	permission.Description = "Updated description"
	permission.UpdatedAt = &timeNow
	permission.Version = &version

	err = repo.UpdatePermission(context.Background(), permission)
	if err != nil {
		t.Errorf("failed to update permission: %v", err)
	} else {
		t.Logf("permission updated successfully: %+v", permission)
	}
}

func TestGetPermissionByCode(t *testing.T) {
	repo := setupTestDB(t)

	// 测试获取存在的权限
	permission, err := repo.GetPermissionByCode(context.Background(), "test_permission_create")
	if err != nil {
		t.Errorf("failed to get permission by code: %v", err)
	} else if permission != nil {
		t.Logf("permission found: %+v", permission)
	} else {
		t.Log("permission not found")
	}

	// 测试获取不存在的权限
	permission, err = repo.GetPermissionByCode(context.Background(), "non_existent_permission")
	if err != nil {
		t.Errorf("failed to get non-existent permission: %v", err)
	} else if permission == nil {
		t.Log("non-existent permission correctly returned nil")
	} else {
		t.Error("expected nil for non-existent permission")
	}
}

func TestGetPermissionByID(t *testing.T) {
	repo := setupTestDB(t)

	// 先通过code获取权限，然后通过ID获取
	permByCode, err := repo.GetPermissionByCode(context.Background(), "test_permission_create")
	if err != nil {
		t.Fatalf("failed to get permission by code: %v", err)
	}
	if permByCode == nil {
		t.Skip("no test permission found, skipping ID test")
		return
	}

	permByID, err := repo.GetPermissionByID(context.Background(), permByCode.ID)
	if err != nil {
		t.Errorf("failed to get permission by ID: %v", err)
	} else if permByID != nil {
		t.Logf("permission found by ID: %+v", permByID)
	} else {
		t.Error("permission not found by ID")
	}
}

func TestCreateRole(t *testing.T) {
	repo := setupTestDB(t)
	uid := id.NewUUID()

	timeNow := time.Now()

	role := &models.Role{
		ID:          id.NewUUID(),
		Code:        "test_role_admin",
		Name:        "Test Admin Role",
		Description: "Role for testing admin purposes",
		Status:      1,
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			UpdatedAt: &timeNow,
			DeletedAt: nil,
			Version:   &version,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}

	err := repo.CreateRole(context.Background(), role)
	if err != nil {
		t.Errorf("failed to create role: %v", err)
	} else {
		t.Logf("role created successfully: %+v", role)
	}
}

func TestUpdateRole(t *testing.T) {
	repo := setupTestDB(t)

	// 获取测试角色
	role, err := repo.GetRoleByCode(context.Background(), "test_role_admin")
	if err != nil {
		t.Fatalf("failed to get role for update test: %v", err)
	}
	if role == nil {
		t.Skip("test role not found, skipping update test")
		return
	}

	// 更新角色
	role.Name = "Updated Test Admin Role"
	role.Description = "Updated description"
	role.UpdatedAt = &timeNow
	role.Version = &version

	err = repo.UpdateRole(context.Background(), role)
	if err != nil {
		t.Errorf("failed to update role: %v", err)
	} else {
		t.Logf("role updated successfully: %+v", role)
	}
}

func TestGetRoleByCode(t *testing.T) {
	repo := setupTestDB(t)

	// 测试获取存在的角色
	role, err := repo.GetRoleByCode(context.Background(), "test_role_admin")
	if err != nil {
		t.Errorf("failed to get role by code: %v", err)
	} else if role != nil {
		t.Logf("role found: %+v", role)
	} else {
		t.Log("role not found")
	}

	// 测试获取不存在的角色
	role, err = repo.GetRoleByCode(context.Background(), "non_existent_role")
	if err != nil {
		t.Errorf("failed to get non-existent role: %v", err)
	} else if role == nil {
		t.Log("non-existent role correctly returned nil")
	} else {
		t.Error("expected nil for non-existent role")
	}
}

func TestGrantPermissionToRole(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.GrantPermissionToRole(context.Background(), "test_permission_create_child", "test_role_admin", &testUserId)
	if err != nil {
		t.Errorf("failed to grant permission to role: %v", err)
	} else {
		t.Log("permission granted to role successfully")
	}
}

func TestGetRolePermission(t *testing.T) {
	repo := setupTestDB(t)

	permissions, err := repo.GetRolePermission(context.Background(), "test_role_admin")
	if err != nil {
		t.Errorf("failed to get role permissions: %v", err)
	} else {
		t.Logf("role permissions: %v", permissions)
	}
}

func TestCreateUserGroup(t *testing.T) {
	repo := setupTestDB(t)
	uid := id.NewUUID()

	userGroup := &models.UserGroup{
		ID:     id.NewUUID(),
		Name:   "test_admin_group",
		Code:   "test_admin_group_code",
		Status: 1,
		Path:   "/admin",
		AuditFields: models.AuditFields{
			CreatedAt: &timeNow,
			UpdatedAt: &timeNow,
			DeletedAt: nil,
			Version:   &version,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}

	err := repo.CreateUserGroup(context.Background(), userGroup)
	if err != nil {
		t.Errorf("failed to create user group: %v", err)
	} else {
		t.Logf("user group created successfully: %+v", userGroup)
	}
}

func TestGetUserGroupByCode(t *testing.T) {
	repo := setupTestDB(t)

	// 测试获取存在的用户组
	userGroup, err := repo.GetUserGroupByCode(context.Background(), "test_admin_group_code")
	if err != nil {
		t.Errorf("failed to get user group by code: %v", err)
	} else if userGroup != nil {
		t.Logf("user group found: %+v", userGroup)
	} else {
		t.Log("user group not found")
	}
}

func TestAssignRoleToUser(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.AssignRoleToUser(context.Background(), "test_role_admin", testUserId, &testUserId)
	if err != nil {
		t.Errorf("failed to assign role to user: %v", err)
	} else {
		t.Log("role assigned to user successfully")
	}
}

func TestGetUserRoles(t *testing.T) {
	repo := setupTestDB(t)

	roles, err := repo.GetUserRoles(context.Background(), testUserId)
	if err != nil {
		t.Errorf("failed to get user roles: %v", err)
	} else {
		t.Logf("user roles: %v", roles)
	}
}

func TestAssignUserToGroup(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.AssignUserToGroup(context.Background(), testUserId, "test_admin_group_code", &testUserId)
	if err != nil {
		t.Errorf("failed to assign user to group: %v", err)
	} else {
		t.Log("user assigned to group successfully")
	}
}

func TestGetUserGroups(t *testing.T) {
	repo := setupTestDB(t)

	groups, err := repo.GetUserGroups(context.Background(), testUserId)
	if err != nil {
		t.Errorf("failed to get user groups: %v", err)
	} else {
		t.Logf("user groups: %v", groups)
	}
}

func TestGetUserGroupMembers(t *testing.T) {
	repo := setupTestDB(t)

	members, err := repo.GetUserGroupMembers(context.Background(), "test_admin_group")
	if err != nil {
		t.Errorf("failed to get user group members: %v", err)
	} else {
		t.Logf("user group members: %v", members)
	}
}

func TestAssignRoleToUserGroup(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.AssignRoleToUserGroup(context.Background(), "test_role_admin", "test_admin_group_code", &testUserId)
	if err != nil {
		t.Errorf("failed to assign role to user group: %v", err)
	} else {
		t.Log("role assigned to user group successfully")
	}
}

func TestRemoveRoleFromUserGroup(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.RemoveRoleFromUserGroup(context.Background(), "test_role_admin", "test_admin_group_code", &testUserId)
	if err != nil {
		t.Errorf("failed to remove role from user group: %v", err)
	} else {
		t.Log("role removed from user group successfully")
	}
}

func TestGetUserPermissions(t *testing.T) {
	repo := setupTestDB(t)

	permissions, err := repo.GetUserPermissions(context.Background(), testUserId)
	if err != nil {
		t.Errorf("failed to get user permissions: %v", err)
	} else {
		t.Logf("user permissions: %v", permissions)
	}
}

func TestHasPermission(t *testing.T) {
	repo := setupTestDB(t)

	hasPermission := repo.HasPermission(context.Background(), testUserId, "test_permission_create")
	t.Logf("user has permission 'test_permission_create': %v", hasPermission)

	hasPermission = repo.HasPermission(context.Background(), testUserId, "non_existent_permission")
	t.Logf("user has permission 'non_existent_permission': %v", hasPermission)
}

func TestCanAccess(t *testing.T) {
	repo := setupTestDB(t)

	canAccess := repo.CanAccess(context.Background(), testUserId, "/test/resource/create", "POST")
	t.Logf("user can access '/test/resource/create' with 'POST': %v", canAccess)

	canAccess = repo.CanAccess(context.Background(), testUserId, "/forbidden/resource", "DELETE")
	t.Logf("user can access '/forbidden/resource' with 'DELETE': %v", canAccess)
}

func TestGetRoleList(t *testing.T) {
	repo := setupTestDB(t)

	roles, err := repo.GetRoleList(context.Background(), 1, 10)
	if err != nil {
		t.Errorf("failed to get role list: %v", err)
	} else {
		t.Logf("role list (page 1, size 10): %d roles found", len(roles))
		for _, role := range roles {
			t.Logf("  - %s: %s", role.Code, role.Name)
		}
	}
}

func TestGetPermissionList(t *testing.T) {
	repo := setupTestDB(t)

	permissions, err := repo.GetPermissionList(context.Background(), 1, 10)
	if err != nil {
		t.Errorf("failed to get permission list: %v", err)
	} else {
		t.Logf("permission list (page 1, size 10): %d permissions found", len(permissions))
		for _, perm := range permissions {
			t.Logf("  - %s: %s", perm.Code, perm.Name)
		}
	}
}

func TestGetUserGroupList(t *testing.T) {
	repo := setupTestDB(t)

	groups, err := repo.GetUserGroupList(context.Background(), 1, 10)
	if err != nil {
		t.Errorf("failed to get user group list: %v", err)
	} else {
		t.Logf("user group list (page 1, size 10): %d groups found", len(groups))
		for _, group := range groups {
			t.Logf("  - %s: %s", group.Code, group.Name)
		}
	}
}

func TestRevokePermissionFromRole(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.RevokePermissionFromRole(context.Background(), "test_permission_create", "test_role_admin", &testUserId)
	if err != nil {
		t.Errorf("failed to revoke permission from role: %v", err)
	} else {
		t.Log("permission revoked from role successfully")
	}
}

func TestRevokeRoleFromUser(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.RevokeRoleFromUser(context.Background(), "test_role_admin", testUserId, &testUserId)
	if err != nil {
		t.Errorf("failed to revoke role from user: %v", err)
	} else {
		t.Log("role revoked from user successfully")
	}
}

func TestRevokeUserFromGroup(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.RevokeUserFromGroup(context.Background(), testUserId, "test_admin_group_code", &testUserId)
	if err != nil {
		t.Errorf("failed to revoke user from group: %v", err)
	} else {
		t.Log("user revoked from group successfully")
	}
}

func TestDeletePermission(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.DeletePermission(context.Background(), "test_permission_create", &testUserId)
	if err != nil {
		t.Errorf("failed to delete permission: %v", err)
	} else {
		t.Log("permission deleted successfully")
	}
}

func TestDeleteRole(t *testing.T) {
	repo := setupTestDB(t)

	err := repo.DeleteRole(context.Background(), "test_role_admin", &testUserId)
	if err != nil {
		t.Errorf("failed to delete role: %v", err)
	} else {
		t.Log("role deleted successfully")
	}
}

func TestDeleteUserGroup(t *testing.T) {
	repo := setupTestDB(t)

	// 先获取用户组ID
	userGroup, err := repo.GetUserGroupByCode(context.Background(), "test_admin_group")
	if err != nil {
		t.Errorf("failed to get user group for deletion: %v", err)
		return
	}
	if userGroup == nil {
		t.Log("user group not found, skipping deletion test")
		return
	}

	err = repo.DeleteUserGroup(context.Background(), string(userGroup.ID[:]), &testUserId)
	if err != nil {
		t.Errorf("failed to delete user group: %v", err)
	} else {
		t.Log("user group deleted successfully")
	}
}
