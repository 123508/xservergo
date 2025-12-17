package validate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

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

// IsValidateString 检查字符串是否可作为符合微软规范的有效文件名。它首先进行基础格式校验，然后进行系统保留字校验。
func IsValidateString(name string) error {
	// 1. 基础格式校验 (长度、非法字符)
	if err := validateFormat(name); err != nil {
		return err
	}

	// 2. 系统保留字校验
	if err := validateReservedNames(name); err != nil {
		return err
	}

	return nil
}

// validateFormat 校验文件名长度和是否包含非法字符。
func validateFormat(filename string) error {
	// 检查是否为空
	if len(filename) == 0 {
		return fmt.Errorf("文件名不能为空")
	}

	// 检查长度（通常不超过255字符，考虑具体文件系统限制）
	if utf8.RuneCountInString(filename) > 255 {
		return fmt.Errorf("文件名长度超过系统限制")
	}

	// 定义Windows文件名中的非法字符集
	illegalChars := `\/:*?"<>|`
	if strings.ContainsAny(filename, illegalChars) {
		return fmt.Errorf("文件名包含非法字符: %s", illegalChars)
	}

	// 检查首尾字符（不能以空格或点结尾）
	if strings.HasSuffix(filename, " ") || strings.HasSuffix(filename, ".") {
		return fmt.Errorf("文件名不能以空格或点结尾")
	}

	return nil
}

// validateReservedNames 校验文件名是否为系统保留字。
func validateReservedNames(filename string) error {
	// 提取文件名（去掉路径和扩展名的主要部分进行比较更稳妥，这里假设传入的是纯文件名）
	nameWithoutExt := strings.ToUpper(filename) // 不区分大小写
	if idx := strings.LastIndex(nameWithoutExt, "."); idx != -1 {
		nameWithoutExt = nameWithoutExt[:idx]
	}

	// 定义Windows保留的设备名称
	reservedNames := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}

	for _, reserved := range reservedNames {
		if nameWithoutExt == reserved {
			return fmt.Errorf("文件名不能是系统保留字: %s", reserved)
		}
	}

	return nil
}
