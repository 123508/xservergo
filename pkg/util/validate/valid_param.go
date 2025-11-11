package validate

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/badoux/checkmail"
	"github.com/gabriel-vasile/mimetype"
	"github.com/nyaruka/phonenumbers"
)

// 严格E.164正则（符合ITU标准）
var e164Regex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// IsValidateE164Phone 严格验证 E.164 格式手机号
func IsValidateE164Phone(phone string) (ok bool, countryNum string, nationalNum string) {
	// 1. 基础格式校验（快速失败）
	if matched := e164Regex.MatchString(phone); !matched {
		return false, "", ""
	}

	// 2. 解析电话号码（核心步骤）
	num, err := phonenumbers.Parse(phone, "")
	if err != nil {
		return false, "", ""
	}

	// 3. 验证号码有效性（使用库的权威校验）
	if !phonenumbers.IsValidNumber(num) {
		return false, "", ""
	}

	// 4. 验证国家码存在
	if num.CountryCode == nil {
		return false, "", ""
	}

	// 5. 验证国内号码存在
	if num.NationalNumber == nil {
		return false, "", ""
	}

	// 6. 返回标准化结果
	return true, strconv.Itoa(int(*num.CountryCode)), strconv.FormatUint(*num.NationalNumber, 10)
}

// IsValidateEmail 严格校验 (格式规范 + 域名解析)
func IsValidateEmail(email string) bool {
	// 1. 基础格式校验 (RFC 5322)
	if err := checkmail.ValidateFormat(email); err != nil {
		return false
	}

	// 2. 域名解析校验 (DNS MX记录)
	if err := checkmail.ValidateHost(email); err != nil {
		return false
	}

	return true
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func IsValidateUsername(username string) bool {
	// 检查是否只包含允许的字符
	if !usernameRegex.MatchString(username) {
		return false
	}

	// 检查是否包含至少一个字母
	containsLetter := strings.ContainsAny(username, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	return containsLetter
}

func IsValidateGender(gender uint64) bool {
	return gender == 0 || gender == 1 || gender == 2
}

func IsValidateFile(fileName string) bool {
	// 定义允许的MIME类型白名单
	allowedMimeTypes := map[string]bool{
		// 图像类型
		"image/jpeg":    true,
		"image/png":     true,
		"image/gif":     true,
		"image/webp":    true,
		"image/bmp":     true,
		"image/svg+xml": true,

		// 文档类型
		"application/pdf":    true,
		"application/msword": true,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
		"application/vnd.ms-excel": true,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
		"application/vnd.ms-powerpoint":                                             true,
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,

		// 文本和源代码类型
		"text/plain":         true,
		"text/html":          true,
		"text/css":           true,
		"text/csv":           true,
		"application/json":   true,
		"application/xml":    true,
		"text/x-go":          true,
		"text/x-python":      true,
		"text/x-java":        true,
		"text/x-c":           true,
		"text/x-c++":         true,
		"text/x-javascript":  true,
		"text/x-php":         true,
		"text/x-ruby":        true,
		"text/x-shellscript": true,
		"text/x-sql":         true,

		// 归档类型
		"application/zip":              true,
		"application/x-rar-compressed": true,
		"application/x-tar":            true,
		"application/gzip":             true,
	}

	// 使用mimetype检测文件的真实MIME类型
	mtype, err := mimetype.DetectFile(fileName)
	if err != nil {
		return false // 文件读取失败，视为无效
	}

	// 检查检测到的MIME类型是否在白名单中
	mimeType := mtype.String()
	if _, allowed := allowedMimeTypes[mimeType]; allowed {
		return true // 文件类型符合白名单要求
	}

	return false // 文件类型不在白名单中
}
