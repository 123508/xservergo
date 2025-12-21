package common

import "github.com/123508/xservergo/kitex_gen/user"

func ParseUserInfoToMap(info *user.UserInfo, other ...map[string]interface{}) map[string]interface{} {

	result := make(map[string]interface{})

	for _, item := range other {
		for k, v := range item {
			result[k] = v
		}
	}

	if info == nil {
		return result
	}

	if info.UserId != "" {
		result["user_id"] = info.UserId
	}

	if info.Username != "" {
		result["username"] = info.Username
	}

	if info.Nickname != "" {
		result["nickname"] = info.Nickname
	}

	if info.Email != "" {
		result["email"] = info.Email
	}

	if info.Phone != "" {
		result["phone"] = info.Phone
	}

	if info.Gender != 0 {
		result["gender"] = info.Gender
	}

	if info.Avatar != "" {
		result["avatar"] = info.Avatar
	}

	if info.Status != 0 {
		result["status"] = info.Status
	}

	return result
}

func ParseOperationToMap(op *user.OperationResult, other ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, item := range other {
		for k, v := range item {
			result[k] = v
		}
	}

	if op == nil {
		return result
	}

	if op.RequestId != "" {
		result["request_id"] = op.RequestId
	}

	if op.Timestamp != "" {
		result["timestamp"] = op.Timestamp
	}

	if op.Version != 0 {
		result["version"] = op.Version
	}

	if op.RequestUserId != "" {
		result["request_user_id"] = op.RequestUserId
	}

	return result
}
