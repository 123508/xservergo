package middleware

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/123508/xservergo/kitex_gen/auth"
	"github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/pkg/cli"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/cloudwego/kitex/pkg/endpoint"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
)

var authClient authservice.Client

func init() {
	authClient = cli.InitAuthService()
}

// replaceTemplateString 替换字符串中 {{ }} 部分为结构体中的值
func replaceTemplateString(s string, request interface{}) (string, error) {
	// 使用正则表达式提取 {{ }} 中的内容
	re := regexp.MustCompile(`\{\{\s*(.*?)\s*}}`)
	matches := re.FindAllStringSubmatch(s, -1)
	for _, match := range matches {
		v := reflect.ValueOf(request).Elem()
		fieldNames := strings.Split(strings.TrimSpace(match[1]), ".")
		for _, fieldName := range fieldNames {
			v = v.FieldByName(fieldName)
			if v.Kind() == reflect.Ptr { // 判断v是否为指针
				if v.IsNil() {
					return "", fmt.Errorf("field %s is nil", fieldName)
				}
				v = v.Elem() // 获取指针指向的值
			}
		}
		if v.IsValid() && v.Kind() == reflect.String {
			value := v.String() // 获取到的值
			fmt.Println(value)
			// 替换原字符串中的 {{ }} 部分
			s = strings.Replace(s, match[0], value, 1)
		}
	}
	return strings.Trim(s, " "), nil
}

// 验证规则是否满足
func checkRule(ctx context.Context, requestUserId string, rule *auth.PolicyRule, request interface{}) bool {
	if strings.Trim(rule.AttributeKey, " ") == "{{ Roles }}" && rule.AttributeType == "List" {
		return checkRuleRole(ctx, requestUserId, rule, request)
	} else if strings.Trim(rule.AttributeKey, " ") == "{{ Groups }}" && rule.AttributeType == "List" {
		return checkRuleGroup(ctx, requestUserId, rule, request)
	} else if rule.AttributeType == "String" {
		return checkRuleString(rule, request)
	}
	return false
}

func checkRuleRole(ctx context.Context, requestUserId string, rule *auth.PolicyRule, request interface{}) bool {
	roles, err := authClient.GetUserRoles(ctx, &auth.GetUserRolesReq{
		TargetUserId:  requestUserId,
		RequestUserId: id.SystemUUID.MarshalBase64(),
	})
	if err != nil {
		return false
	}

	targetRole, err := replaceTemplateString(rule.AttributeValue, request)
	if err != nil {
		return false
	}

	if rule.Operator == "Contains" {
		for _, role := range roles.Roles {
			if role.Code == targetRole {
				return true
			}
		}
		return false
	}

	return false
}

func checkRuleGroup(ctx context.Context, requestUserId string, rule *auth.PolicyRule, request interface{}) bool {
	groups, err := authClient.GetUserGroups(ctx, &auth.GetUserGroupsReq{
		TargetUserId:  requestUserId,
		RequestUserId: id.SystemUUID.MarshalBase64(),
	})
	if err != nil {
		return false
	}

	targetGroup, err := replaceTemplateString(rule.AttributeKey, request)
	if err != nil {
		return false
	}

	if rule.Operator == "Contains" {
		for _, group := range groups.UserGroups {
			if group.Code == targetGroup {
				return true
			}
		}
		return false
	}

	return false
}

func checkRuleString(rule *auth.PolicyRule, request interface{}) bool {
	key, err := replaceTemplateString(rule.AttributeKey, request)
	if err != nil {
		return false
	}
	value, err := replaceTemplateString(rule.AttributeValue, request)
	if err != nil {
		return false
	}
	switch rule.Operator {
	case "=":
		return key == value
	case "!=":
		return key != value
	case ">":
		return key > value
	case "<":
		return key < value
	case ">=":
		return key >= value
	case "<=":
		return key <= value
	case "Contains":
		return strings.Contains(key, value)
	case "StartsWith":
		return strings.HasPrefix(key, value)
	case "EndsWith":
		return strings.HasSuffix(key, value)
	case "Regex":
		matched, err := regexp.MatchString(value, key)
		if err != nil {
			return false
		}
		return matched
	}
	return false
}

func CanAccessMW(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, request, response interface{}) error {
		requestUserId := id.VisitorUserUUID.MarshalBase64() // 默认访客用户
		// 通过反射获取request_user_id
		v := reflect.ValueOf(request)
		requestUserIdField := v.Elem().FieldByName("Req").Elem().FieldByName("RequestUserId")
		if requestUserIdField.IsValid() && requestUserIdField.Kind() == reflect.String {
			requestUserId = requestUserIdField.String()
		}

		// 如果是系统用户, 则直接放行
		if requestUserId == id.SystemUUID.MarshalBase64() {
			return next(ctx, request, response)
		}

		// 从context中获取RPC信息
		methodName := ""
		serviceName := ""
		ri := rpcinfo.GetRPCInfo(ctx)
		if ri != nil {
			methodName = ri.To().Method()       // 获取方法名
			serviceName = ri.To().ServiceName() // 获取服务名
		}

		if methodName == "IssueToken" || methodName == "VerifyToken" || methodName == "refreshToken" || methodName == "GetVersion" {
			// 登录和刷新token不验证权限
			return next(ctx, request, response)
		}

		// 判断是否有权限访问(RBAC)
		canAccessResp, err := authClient.CanAccess(ctx, &auth.CanAccessReq{
			Resource:      serviceName,
			Method:        methodName,
			RequestUserId: requestUserId,
			UserStatus:    0,
		})
		if err != nil {
			return err
		}
		if !canAccessResp.Ok {
			return fmt.Errorf("no permission to access %s %s", serviceName, methodName)
		}

		// ABAC
		if canAccessResp.NeedPolicy {
			pass := true
			for _, policy := range canAccessResp.PolicyRules {
				pass = true
				// 遍历策略中的规则, 只要有一条规则不通过, 就不允许访问
				for _, rule := range policy.Rules {
					if !checkRule(ctx, requestUserId, rule, request) {
						pass = false
						break
					}
				}
				if pass { // 有一条策略通过, 就允许访问
					break
				}
			}
			if !pass { // 所有策略都不通过, 不允许访问
				return fmt.Errorf("no permission to access %s %s by ABAC", serviceName, methodName)
			}
		}

		err = next(ctx, request, response)
		return err
	}
}
