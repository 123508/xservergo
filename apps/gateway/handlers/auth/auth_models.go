package auth

import "github.com/123508/xservergo/kitex_gen/auth"

func permissionTypeToString(typeInt auth.Permission_Type) string {
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

func permissionTypeFromString(typeStr string) auth.Permission_Type {
	switch typeStr {
	case "API":
		return auth.Permission_API
	case "MENU":
		return auth.Permission_MENU
	case "BUTTON":
		return auth.Permission_BUTTON
	case "DATA":
		return auth.Permission_DATA
	case "FIELD":
		return auth.Permission_FIELD
	case "MODULE":
		return auth.Permission_MODULE
	case "FILE":
		return auth.Permission_FILE
	case "TASK":
		return auth.Permission_TASK
	default:
		return auth.Permission_API
	}
}

type Permission struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ParentID    string `json:"parent_id"`
	Type        string `json:"type"`
	Resource    string `json:"resource"`
	Method      string `json:"method"`
	Status      bool   `json:"status"`
}

type Role struct {
	ID          string `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      bool   `json:"status"`
}

type UserGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Code     string `json:"code"`
	Status   bool   `json:"status"`
	ParentID string `json:"parent_id"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Gender   uint64 `json:"gender"`
	Avatar   string `json:"avatar"`
	Status   uint64 `json:"status"`
}
