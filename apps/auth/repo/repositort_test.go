package repo

import (
	"testing"
	"time"

	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
)

func TestCreatePermission(t *testing.T) {
	d, err := db.InitMySQLDB()
	if err != nil {
		t.Fatalf("failed to initialize database: %v", err)
	}
	repo := NewAuthRepository(d)
	uid := util.NewUUID()
	permission := &models.Permission{
		ID:          util.NewUUID(),
		Code:        "test_permission",
		Name:        "Test Permission",
		Description: "Permission for testing purposes",
		ParentID:    nil,
		Type:        models.PermissionTypeAPI,
		Resource:    "/test/resource",
		Method:      "Test",
		Status:      1,
		AuditFields: models.AuditFields{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			DeletedAt: nil,
			Version:   1,
			CreatedBy: &uid,
			UpdatedBy: nil,
		},
	}
	err = repo.CreatePermission(permission)
	if err != nil {
		t.Errorf("failed to create permission: %v", err)
	} else {
		t.Logf("permission created successfully: %+v", permission)
	}
}
