package auth

type PermissionType string

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
