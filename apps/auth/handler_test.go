package main

import (
	"context"
	"testing"

	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/util"
)

var authClient authservice.Client
var userId util.UUID

func init() {
	authClient = cli.InitAuthService()
	userId, _ = util.FromString("01981dbf-1b8a-7039-8d55-f26e2e525c26")
}

func TestAuthServiceImpl_PermissionLifecycle(t *testing.T) {
	// 1. CreatePermission
	userIdBytes, _ := userId.Marshal()
	createPermissionReq := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Id:             nil,
			Code:           "test_permission_create_handler",
			PermissionName: "test_permission_create_handler",
			Description:    "test_permission_create_handler",
			ParentId:       nil,
			Type:           auth.Permission_API,
			Resource:       "test/resource",
			Method:         "GET",
			Status:         true,
		},
		RequestUserId: userIdBytes,
	}

	createResp, err := authClient.CreatePermission(context.Background(), createPermissionReq)
	if err != nil {
		t.Fatalf("CreatePermission failed: %v", err)
	}
	if createResp == nil {
		t.Fatal("CreatePermission response is nil")
	}
	t.Logf("CreatePermission response: %v", createResp)

	// 2. UpdatePermission
	//permissionId, _ := util.FromString("01986b50-f353-7da5-9397-eec56a4cea76")
	//permissionIdBytes, _ := permissionId.Marshal()
	updatePermissionReq := &auth.UpdatePermissionReq{
		Permission: &auth.Permission{
			//Id:             permissionIdBytes, // Code不为空时可以不填写ID
			Code:           "test_permission_create_handler",
			PermissionName: "test_permission_create_handler_update",
			Description:    "test_permission_create_handler_update",
			ParentId:       nil,
			Type:           auth.Permission_FILE,
			Resource:       "test/resource",
			Method:         "GET",
			Status:         true,
		},
		RequestUserId: userIdBytes,
	}
	updateResp, err := authClient.UpdatePermission(context.Background(), updatePermissionReq)
	if err != nil {
		t.Fatalf("UpdatePermission failed: %v", err)
	}
	if updateResp == nil {
		t.Fatal("UpdatePermission response is nil")
	}
	t.Logf("UpdatePermission response: %v", updateResp)

	// 3. GetPermission
	getPermissionReq := &auth.GetPermissionReq{
		PermissionCode: "test_permission_create_handler",
	}
	getResp, err := authClient.GetPermission(context.Background(), getPermissionReq)
	if err != nil {
		t.Fatalf("GetPermission failed: %v", err)
	}
	if getResp == nil {
		t.Fatal("GetPermission response is nil")
	}
	if getResp.PermissionName != "test_permission_create_handler_update" {
		t.Fatalf("Expected permission name to be updated, but got %s", getResp.PermissionName)
	}
	t.Logf("GetPermission response: %v", getResp)

	// 4. DeletePermission
	deletePermissionReq := &auth.DeletePermissionReq{
		PermissionCode: "test_permission_create_handler",
		RequestUserId:  userIdBytes,
	}
	resp, err := authClient.DeletePermission(context.Background(), deletePermissionReq)
	if err != nil {
		t.Fatalf("DeletePermission failed: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatal("DeletePermission response is nil or not successful")
	}
	t.Logf("DeletePermission response: %v", resp)

	// 5. Verify that the permission is deleted
	_, err = authClient.GetPermission(context.Background(), getPermissionReq)
	if err == nil {
		t.Fatal("Expected error when getting deleted permission, but got nil")
	}
	t.Logf("Successfully verified permission deletion: %v", err)
}

func TestAuthServiceImpl_TokenLifecycle(t *testing.T) {
	userIdBytes, _ := userId.Marshal()

	// 1. IssueToken
	issueReq := &auth.IssueTokenReq{UserId: userIdBytes}
	issueResp, err := authClient.IssueToken(context.Background(), issueReq)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if issueResp == nil || issueResp.AccessToken == "" || issueResp.RefreshToken == "" {
		t.Fatal("IssueToken response is invalid")
	}
	t.Logf("IssueToken response: AccessToken=%s, RefreshToken=%s", issueResp.AccessToken, issueResp.RefreshToken)

	// 2. VerifyToken
	verifyReq := &auth.VerifyTokenReq{AccessToken: issueResp.AccessToken}
	verifyResp, err := authClient.VerifyToken(context.Background(), verifyReq)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if verifyResp == nil {
		t.Fatal("VerifyToken response is nil")
	}
	verifiedUserId := &util.UUID{}
	_ = verifiedUserId.Unmarshal(verifyResp.UserId)
	if verifiedUserId.String() != userId.String() {
		t.Fatalf("Verified user ID %s does not match original user ID %s", verifiedUserId.String(), userId.String())
	}
	t.Logf("VerifyToken response: UserId=%s", verifiedUserId.String())

	// 3. RefreshToken
	refreshReq := &auth.RefreshTokenReq{
		AccessToken:  issueResp.AccessToken,
		RefreshToken: issueResp.RefreshToken,
		UserId:       userIdBytes,
	}
	refreshResp, err := authClient.RefreshToken(context.Background(), refreshReq)
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}
	if refreshResp == nil || refreshResp.AccessToken == "" || refreshResp.RefreshToken == "" {
		t.Fatal("RefreshToken response is invalid")
	}
	t.Logf("RefreshToken response: AccessToken=%s, RefreshToken=%s", refreshResp.AccessToken, refreshResp.RefreshToken)

	// 4. Verify new token
	verifyNewReq := &auth.VerifyTokenReq{AccessToken: refreshResp.AccessToken}
	verifyNewResp, err := authClient.VerifyToken(context.Background(), verifyNewReq)
	if err != nil {
		t.Fatalf("VerifyToken after refresh failed: %v", err)
	}
	if verifyNewResp == nil {
		t.Fatal("VerifyToken after refresh response is nil")
	}
	verifiedNewUserId := &util.UUID{}
	_ = verifiedNewUserId.Unmarshal(verifyNewResp.UserId)
	if verifiedNewUserId.String() != userId.String() {
		t.Fatalf("Verified user ID %s after refresh does not match original user ID %s", verifiedNewUserId.String(), userId.String())
	}
	t.Logf("VerifyToken after refresh response: UserId=%s", verifiedNewUserId.String())
}

func TestAuthServiceImpl_RoleLifecycle(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	roleCode := "test_role_handler"

	// 1. CreateRole
	createRoleReq := &auth.CreateRoleReq{
		Role: &auth.Role{
			Code:        roleCode,
			RoleName:    "Test Role Handler",
			Description: "This is a test role from handler test",
		},
		RequestUserId: userIdBytes,
	}
	createResp, err := authClient.CreateRole(context.Background(), createRoleReq)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	if createResp == nil {
		t.Fatal("CreateRole response is nil")
	}
	t.Logf("CreateRole response: %v", createResp)

	// 2. UpdateRole
	updateRoleReq := &auth.UpdateRoleReq{
		Role: &auth.Role{
			Code:        roleCode,
			RoleName:    "Test Role Handler Updated",
			Description: "This is an updated test role",
		},
		RequestUserId: userIdBytes,
	}
	updateResp, err := authClient.UpdateRole(context.Background(), updateRoleReq)
	if err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}
	if updateResp == nil {
		t.Fatal("UpdateRole response is nil")
	}
	if updateResp.RoleName != "Test Role Handler Updated" {
		t.Fatalf("Expected role name to be updated, but got %s", updateResp.RoleName)
	}
	t.Logf("UpdateRole response: %v", updateResp)

	// 3. GetRole
	getRoleReq := &auth.GetRoleReq{RoleCode: roleCode}
	getResp, err := authClient.GetRole(context.Background(), getRoleReq)
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if getResp == nil {
		t.Fatal("GetRole response is nil")
	}
	if getResp.RoleName != "Test Role Handler Updated" {
		t.Fatalf("Expected role name to be 'Test Role Handler Updated', but got %s", getResp.RoleName)
	}
	t.Logf("GetRole response: %v", getResp)

	// 4. GrantPermissionToRole
	permissionCode := "test_permission_create_handler"
	grantReq := &auth.GrantPermissionToRoleReq{
		RoleCode:       roleCode,
		PermissionCode: permissionCode,
		RequestUserId:  userIdBytes,
	}
	grantResp, err := authClient.GrantPermissionToRole(context.Background(), grantReq)
	if err != nil {
		t.Fatalf("GrantPermissionToRole failed: %v", err)
	}
	if grantResp == nil || !grantResp.Success {
		t.Fatal("GrantPermissionToRole was not successful")
	}
	t.Log("GrantPermissionToRole successful")

	// 5. GetRolePermissions
	getPermsReq := &auth.GetRolePermissionsReq{RoleCode: roleCode}
	getPermsResp, err := authClient.GetRolePermissions(context.Background(), getPermsReq)
	if err != nil {
		t.Fatalf("GetRolePermissions failed: %v", err)
	}
	if getPermsResp == nil || len(getPermsResp.Permissions) == 0 {
		t.Fatal("GetRolePermissions returned no permissions")
	}
	found := false
	for _, p := range getPermsResp.Permissions {
		if p.Code == permissionCode {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Granted permission %s not found in role permissions", permissionCode)
	}
	t.Logf("GetRolePermissions response: %v", getPermsResp)

	// 6. RevokePermissionFromRole
	revokeReq := &auth.RevokePermissionFromRoleReq{
		RoleCode:       roleCode,
		PermissionCode: permissionCode,
		RequestUserId:  userIdBytes,
	}
	revokeResp, err := authClient.RevokePermissionFromRole(context.Background(), revokeReq)
	if err != nil {
		t.Fatalf("RevokePermissionFromRole failed: %v", err)
	}
	if revokeResp == nil || !revokeResp.Success {
		t.Fatal("RevokePermissionFromRole was not successful")
	}
	t.Log("RevokePermissionFromRole successful")

	// 7. DeleteRole
	deleteRoleReq := &auth.DeleteRoleReq{
		RoleCode:      roleCode,
		RequestUserId: userIdBytes,
	}
	deleteResp, err := authClient.DeleteRole(context.Background(), deleteRoleReq)
	if err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
	if deleteResp == nil || !deleteResp.Success {
		t.Fatal("DeleteRole was not successful")
	}
	t.Log("DeleteRole successful")

	// Verify deletion
	_, err = authClient.GetRole(context.Background(), getRoleReq)
	if err == nil {
		t.Fatal("Expected error when getting deleted role, but got nil")
	}
	t.Logf("Successfully verified role deletion: %v", err)
}

func TestAuthServiceImpl_UserGroupLifecycle(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	groupCode := "test_group_handler"

	// 1. CreateUserGroup
	createReq := &auth.CreateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      groupCode,
			GroupName: "Test Group Handler",
		},
		RequestUserId: userIdBytes,
	}
	createResp, err := authClient.CreateUserGroup(context.Background(), createReq)
	if err != nil {
		t.Fatalf("CreateUserGroup failed: %v", err)
	}
	if createResp == nil {
		t.Fatal("CreateUserGroup response is nil")
	}
	t.Logf("CreateUserGroup response: %v", createResp)

	// 2. UpdateUserGroup
	updateReq := &auth.UpdateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      groupCode,
			GroupName: "Test Group Handler Updated",
		},
		RequestUserId: userIdBytes,
	}
	updateResp, err := authClient.UpdateUserGroup(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("UpdateUserGroup failed: %v", err)
	}
	if updateResp == nil {
		t.Fatal("UpdateUserGroup response is nil")
	}
	if updateResp.GroupName != "Test Group Handler Updated" {
		t.Fatalf("Expected group name to be updated, but got %s", updateResp.GroupName)
	}
	t.Logf("UpdateUserGroup response: %v", updateResp)

	// 3. GetUserGroup
	getReq := &auth.GetUserGroupReq{UserGroupCode: groupCode}
	getResp, err := authClient.GetUserGroup(context.Background(), getReq)
	if err != nil {
		t.Fatalf("GetUserGroup failed: %v", err)
	}
	if getResp == nil {
		t.Fatal("GetUserGroup response is nil")
	}
	if getResp.GroupName != "Test Group Handler Updated" {
		t.Fatalf("Expected group name to be 'Test Group Handler Updated', but got %s", getResp.GroupName)
	}
	t.Logf("GetUserGroup response: %v", getResp)

	// 4. DeleteUserGroup
	deleteReq := &auth.DeleteUserGroupReq{
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	deleteResp, err := authClient.DeleteUserGroup(context.Background(), deleteReq)
	if err != nil {
		t.Fatalf("DeleteUserGroup failed: %v", err)
	}
	if deleteResp == nil || !deleteResp.Success {
		t.Fatal("DeleteUserGroup was not successful")
	}
	t.Log("DeleteUserGroup successful")

	// Verify deletion
	_, err = authClient.GetUserGroup(context.Background(), getReq)
	if err == nil {
		t.Fatal("Expected error when getting deleted group, but got nil")
	}
	t.Logf("Successfully verified group deletion: %v", err)
}

func TestAuthServiceImpl_UserGroupAssignment(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	groupCode := "test_group_for_user_assignment"

	// Setup: Create a group first
	createReq := &auth.CreateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      groupCode,
			GroupName: "Test Group for User Assignment",
		},
		RequestUserId: userIdBytes,
	}
	_, err := authClient.CreateUserGroup(context.Background(), createReq)
	if err != nil {
		t.Fatalf("Setup: CreateUserGroup failed: %v", err)
	}

	// 1. AssignUserToGroup
	assignReq := &auth.AssignUserToGroupReq{
		TargetUserId:  userIdBytes,
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	assignResp, err := authClient.AssignUserToGroup(context.Background(), assignReq)
	if err != nil {
		t.Fatalf("AssignUserToGroup failed: %v", err)
	}
	if assignResp == nil || !assignResp.Success {
		t.Fatal("AssignUserToGroup was not successful")
	}
	t.Log("AssignUserToGroup successful")

	// 2. GetUserGroupMembers
	getMembersReq := &auth.GetUserGroupMembersReq{UserGroupCode: groupCode}
	getMembersResp, err := authClient.GetUserGroupMembers(context.Background(), getMembersReq)
	if err != nil {
		t.Fatalf("GetUserGroupMembers failed: %v", err)
	}
	if getMembersResp == nil || len(getMembersResp.Users) == 0 {
		t.Fatal("GetUserGroupMembers returned no members")
	}
	found := false
	for _, member := range getMembersResp.Users {
		memberId := &util.UUID{}
		_ = memberId.Unmarshal(member.UserId)
		if memberId.String() == userId.String() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Assigned user %s not found in group members", userId.String())
	}
	t.Logf("GetUserGroupMembers response: %v", getMembersResp)

	// Also test GetUserGroups
	getUserGroupsReq := &auth.GetUserGroupsReq{TargetUserId: userIdBytes}
	getUserGroupsResp, err := authClient.GetUserGroups(context.Background(), getUserGroupsReq)
	if err != nil {
		t.Fatalf("GetUserGroups failed: %v", err)
	}
	if getUserGroupsResp == nil || len(getUserGroupsResp.UserGroups) == 0 {
		t.Fatal("GetUserGroups returned no groups")
	}
	foundGroup := false
	for _, g := range getUserGroupsResp.UserGroups {
		if g.Code == groupCode {
			foundGroup = true
			break
		}
	}
	if !foundGroup {
		t.Fatalf("Assigned group %s not found for user", groupCode)
	}
	t.Logf("GetUserGroups response: %v", getUserGroupsResp)

	// 3. RemoveUserFromGroup
	removeReq := &auth.RemoveUserFromGroupReq{
		TargetUserId:  userIdBytes,
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	removeResp, err := authClient.RemoveUserFromGroup(context.Background(), removeReq)
	if err != nil {
		t.Fatalf("RemoveUserFromGroup failed: %v", err)
	}
	if removeResp == nil || !removeResp.Success {
		t.Fatal("RemoveUserFromGroup was not successful")
	}
	t.Log("RemoveUserFromGroup successful")

	// Verify removal
	getMembersRespAfterRemove, err := authClient.GetUserGroupMembers(context.Background(), getMembersReq)
	if err != nil {
		t.Fatalf("GetUserGroupMembers after removal failed: %v", err)
	}
	foundAfterRemove := false
	for _, member := range getMembersRespAfterRemove.Users {
		memberId := &util.UUID{}
		_ = memberId.Unmarshal(member.UserId)
		if memberId.String() == userId.String() {
			foundAfterRemove = true
			break
		}
	}
	if foundAfterRemove {
		t.Fatal("User was not removed from group")
	}
	t.Log("Successfully verified user removal from group")

	// Teardown: Delete the group
	deleteReq := &auth.DeleteUserGroupReq{
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	_, err = authClient.DeleteUserGroup(context.Background(), deleteReq)
	if err != nil {
		t.Logf("Teardown: DeleteUserGroup failed: %v", err)
	}
}

func TestAuthServiceImpl_UserGroupRoleAssignment(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	roleCode := "test_role_for_group_assignment"
	groupCode := "test_group_for_role_assignment"
	permissionCode := "test_permission_for_group_role"

	// Setup: Create a permission
	createPermReq := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Code:           permissionCode,
			PermissionName: "Test Permission for Group Role",
			Type:           auth.Permission_API,
			Resource:       "/test/group_role",
			Method:         "POST",
		},
		RequestUserId: userIdBytes,
	}
	_, err := authClient.CreatePermission(context.Background(), createPermReq)
	if err != nil {
		// If it already exists, ignore the error for test idempotency
		t.Logf("Setup: CreatePermission might have failed if already exists: %v", err)
	}

	// Setup: Create a role
	createRoleReq := &auth.CreateRoleReq{
		Role: &auth.Role{
			Code:        roleCode,
			RoleName:    "Test Role for Group Assignment",
			Description: "A role for testing group assignment",
		},
		RequestUserId: userIdBytes,
	}
	_, err = authClient.CreateRole(context.Background(), createRoleReq)
	if err != nil {
		t.Logf("Setup: CreateRole might have failed if already exists: %v", err)
	}

	// Setup: Grant permission to role
	grantReq := &auth.GrantPermissionToRoleReq{
		RoleCode:       roleCode,
		PermissionCode: permissionCode,
		RequestUserId:  userIdBytes,
	}
	_, err = authClient.GrantPermissionToRole(context.Background(), grantReq)
	if err != nil {
		t.Logf("Setup: GrantPermissionToRole might have failed if already exists: %v", err)
	}

	// Setup: Create a group
	createGroupReq := &auth.CreateUserGroupReq{
		UserGroup: &auth.UserGroup{
			Code:      groupCode,
			GroupName: "Test Group for Role Assignment",
		},
		RequestUserId: userIdBytes,
	}
	_, err = authClient.CreateUserGroup(context.Background(), createGroupReq)
	if err != nil {
		t.Logf("Setup: CreateUserGroup might have failed if already exists: %v", err)
	}

	// 1. AssignRoleToUserGroup
	assignReq := &auth.AssignRoleToUserGroupReq{
		RoleCode:      roleCode,
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	assignResp, err := authClient.AssignRoleToUserGroup(context.Background(), assignReq)
	if err != nil {
		t.Fatalf("AssignRoleToUserGroup failed: %v", err)
	}
	if assignResp == nil || !assignResp.Success {
		t.Fatal("AssignRoleToUserGroup was not successful")
	}
	t.Log("AssignRoleToUserGroup successful")

	// 2. Assign user to group to check permissions
	assignUserReq := &auth.AssignUserToGroupReq{
		TargetUserId:  userIdBytes,
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	_, err = authClient.AssignUserToGroup(context.Background(), assignUserReq)
	if err != nil {
		t.Fatalf("Setup: AssignUserToGroup failed: %v", err)
	}

	// 3. GetUserPermissions to verify
	getPermsReq := &auth.GetUserPermissionsReq{TargetUserId: userIdBytes}
	getPermsResp, err := authClient.GetUserPermissions(context.Background(), getPermsReq)
	if err != nil {
		t.Fatalf("GetUserPermissions failed: %v", err)
	}
	if getPermsResp == nil || len(getPermsResp.Permissions) == 0 {
		t.Fatal("GetUserPermissions returned no permissions")
	}
	foundPerm := false
	for _, p := range getPermsResp.Permissions {
		if p.Code == permissionCode {
			foundPerm = true
			break
		}
	}
	if !foundPerm {
		t.Fatalf("Permission %s not found for user through group role", permissionCode)
	}
	t.Log("GetUserPermissions successful, permission verified")

	// 4. RemoveRoleFromUserGroup
	removeReq := &auth.RemoveRoleFromUserGroupReq{
		RoleCode:      roleCode,
		UserGroupCode: groupCode,
		RequestUserId: userIdBytes,
	}
	removeResp, err := authClient.RemoveRoleFromUserGroup(context.Background(), removeReq)
	if err != nil {
		t.Fatalf("RemoveRoleFromUserGroup failed: %v", err)
	}
	if removeResp == nil || !removeResp.Success {
		t.Fatal("RemoveRoleFromUserGroup was not successful")
	}
	t.Log("RemoveRoleFromUserGroup successful")

	// Verify removal by checking permissions again
	getPermsRespAfter, err := authClient.GetUserPermissions(context.Background(), getPermsReq)
	if err != nil {
		t.Fatalf("GetUserPermissions after removal failed: %v", err)
	}
	foundPermAfter := false
	for _, p := range getPermsRespAfter.Permissions {
		if p.Code == permissionCode {
			foundPermAfter = true
			break
		}
	}
	if foundPermAfter {
		t.Fatal("Permission was not removed after revoking group role")
	}
	t.Log("Successfully verified role removal from group")

	// Teardown
	_, _ = authClient.RemoveUserFromGroup(context.Background(), &auth.RemoveUserFromGroupReq{TargetUserId: userIdBytes, UserGroupCode: groupCode, RequestUserId: userIdBytes})
	_, _ = authClient.DeleteUserGroup(context.Background(), &auth.DeleteUserGroupReq{UserGroupCode: groupCode, RequestUserId: userIdBytes})
	_, _ = authClient.DeleteRole(context.Background(), &auth.DeleteRoleReq{RoleCode: roleCode, RequestUserId: userIdBytes})
	_, _ = authClient.DeletePermission(context.Background(), &auth.DeletePermissionReq{PermissionCode: permissionCode, RequestUserId: userIdBytes})
}

func TestAuthServiceImpl_ListFunctions(t *testing.T) {
	// 1. ListPermissions
	listPermsReq := &auth.ListPermissionsReq{Page: 1, PageSize: 10}
	listPermsResp, err := authClient.ListPermissions(context.Background(), listPermsReq)
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}
	if listPermsResp == nil {
		t.Fatal("ListPermissions response is nil")
	}
	t.Logf("permissions, total: %d, Permissions: %v", len(listPermsResp.Perms), listPermsResp.Perms)

	// 2. ListRoles
	listRolesReq := &auth.ListRolesReq{Page: 1, PageSize: 10}
	listRolesResp, err := authClient.ListRoles(context.Background(), listRolesReq)
	if err != nil {
		t.Fatalf("ListRoles failed: %v", err)
	}
	if listRolesResp == nil {
		t.Fatal("ListRoles response is nil")
	}
	t.Logf("roles, total: %d, Roles: %v ", len(listRolesResp.Roles), listRolesResp.Roles)

	// 3. ListUserGroups
	listGroupsReq := &auth.ListUserGroupsReq{Page: 1, PageSize: 10}
	listGroupsResp, err := authClient.ListUserGroups(context.Background(), listGroupsReq)
	if err != nil {
		t.Fatalf("ListUserGroups failed: %v", err)
	}
	if listGroupsResp == nil {
		t.Fatal("ListUserGroups response is nil")
	}
	t.Logf("groups, total: %d, Groups: %v ", len(listGroupsResp.UserGroups), listGroupsResp.UserGroups)
}

func TestAuthServiceImpl_PermissionChecks(t *testing.T) {
	userIdBytes, _ := userId.Marshal()
	permissionCode := "test_permission_for_checks"
	resource := "/test/permission_checks"
	method := "GET"

	// Setup: Create a permission
	createPermReq := &auth.CreatePermissionReq{
		Permission: &auth.Permission{
			Code:           permissionCode,
			PermissionName: "Test Permission for Checks",
			Type:           auth.Permission_API,
			Resource:       resource,
			Method:         method,
		},
		RequestUserId: userIdBytes,
	}
	_, err := authClient.CreatePermission(context.Background(), createPermReq)
	if err != nil {
		t.Logf("Setup: CreatePermission might have failed if already exists: %v", err)
	}

	// 1. HasPermission (without permission)
	hasPermReq := &auth.HasPermissionReq{
		TargetUserId:   userIdBytes,
		PermissionCode: permissionCode,
	}
	hasPermResp, err := authClient.HasPermission(context.Background(), hasPermReq)
	if err != nil {
		t.Fatalf("HasPermission (before grant) failed: %v", err)
	}
	if hasPermResp.Ok {
		t.Fatal("Expected user to not have permission before grant")
	}
	t.Log("HasPermission (before grant) check successful")

	// 2. CanAccess (without permission)
	canAccessReq := &auth.CanAccessReq{
		TargetUserId: userIdBytes,
		Resource:     resource,
		Method:       method,
	}
	canAccessResp, err := authClient.CanAccess(context.Background(), canAccessReq)
	if err != nil {
		t.Fatalf("CanAccess (before grant) failed: %v", err)
	}
	if canAccessResp.Ok {
		t.Fatal("Expected user to not have access before grant")
	}
	t.Log("CanAccess (before grant) check successful")

	// Setup: Create a role and grant permission to it
	roleCode := "test_role_for_checks"
	createRoleReq := &auth.CreateRoleReq{
		Role:          &auth.Role{Code: roleCode, RoleName: "Test Role for Checks"},
		RequestUserId: userIdBytes,
	}
	_, err = authClient.CreateRole(context.Background(), createRoleReq)
	if err != nil {
		t.Logf("Setup: CreateRole might have failed if already exists: %v", err)
	}

	grantReq := &auth.GrantPermissionToRoleReq{
		RoleCode:       roleCode,
		PermissionCode: permissionCode,
		RequestUserId:  userIdBytes,
	}
	_, err = authClient.GrantPermissionToRole(context.Background(), grantReq)
	if err != nil {
		t.Logf("Setup: GrantPermissionToRole might have failed if already exists: %v", err)
	}

	// Setup: Assign role to user
	assignReq := &auth.AssignRoleToUserReq{
		TargetUserId:  userIdBytes,
		RoleCode:      roleCode,
		RequestUserId: userIdBytes,
	}
	_, err = authClient.AssignRoleToUser(context.Background(), assignReq)
	if err != nil {
		t.Fatalf("Setup: AssignRoleToUser failed: %v", err)
	}

	// 3. HasPermission (with permission)
	hasPermRespAfter, err := authClient.HasPermission(context.Background(), hasPermReq)
	if err != nil {
		t.Fatalf("HasPermission (after grant) failed: %v", err)
	}
	if !hasPermRespAfter.Ok {
		t.Fatal("Expected user to have permission after grant")
	}
	t.Log("HasPermission (after grant) check successful")

	// 4. CanAccess (with permission)
	canAccessRespAfter, err := authClient.CanAccess(context.Background(), canAccessReq)
	if err != nil {
		t.Fatalf("CanAccess (after grant) failed: %v", err)
	}
	if !canAccessRespAfter.Ok {
		t.Fatal("Expected user to have access after grant")
	}
	t.Log("CanAccess (after grant) check successful")

	// Teardown
	_, _ = authClient.RemoveRoleFromUser(context.Background(), &auth.RemoveRoleFromUserReq{TargetUserId: userIdBytes, RoleCode: roleCode, RequestUserId: userIdBytes})
	_, _ = authClient.DeleteRole(context.Background(), &auth.DeleteRoleReq{RoleCode: roleCode, RequestUserId: userIdBytes})
	_, _ = authClient.DeletePermission(context.Background(), &auth.DeletePermissionReq{PermissionCode: permissionCode, RequestUserId: userIdBytes})
}
