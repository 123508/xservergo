package auth

import "github.com/123508/xservergo/kitex_gen/auth"

type PermissionType string

func permissionType(typeInt auth.Permission_Type) string {
	switch typeInt {
	case auth.Permission_API:
		return "API"
	case auth.Permission_MENU:
		return "MENU"
	case auth.Permission_BUTTON:
		return "BUTTON"
	case auth.Permission_DATA:
		return "DATA"
	case auth.Permission_FIELD:
		return "FIELD"
	case auth.Permission_MODULE:
		return "MODULE"
	case auth.Permission_FILE:
		return "FILE"
	case auth.Permission_TASK:
		return "TASK"
	default:
		return "API"
	}
}

type Permission struct {
	ID          string `json:"id"`
	Code        string `json:"code,required"`
	Name        string `json:"name,required"`
	Description string `json:"description"`
	ParentID    string `json:"parent_id"`
	Type        string `json:"type,required"`
	Resource    string `json:"resource"`
	Method      string `json:"method"`
	Status      bool   `json:"status"`
}
