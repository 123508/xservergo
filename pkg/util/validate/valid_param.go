package validate

import (
	"github.com/badoux/checkmail"
	"github.com/nyaruka/phonenumbers"
	"regexp"
	"strconv"
	"strings"
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
