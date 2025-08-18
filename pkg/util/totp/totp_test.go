package totp

import (
	"encoding/base32"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTOTP_checkAndRepair(t *testing.T) {
	tests := []struct {
		name     string
		totp     *TOTP
		expected *TOTP
	}{
		{
			name: "all fields empty",
			totp: &TOTP{},
			expected: &TOTP{
				Interval: 30,
				Issuer:   "XServerGo",
				Username: "DefaultUser",
			},
		},
		{
			name: "custom interval",
			totp: &TOTP{
				Interval: 60,
			},
			expected: &TOTP{
				Interval: 60,
				Issuer:   "XServerGo",
				Username: "DefaultUser",
			},
		},
		{
			name: "negative interval should be reset to 30",
			totp: &TOTP{
				Interval: -10,
			},
			expected: &TOTP{
				Interval: 30,
				Issuer:   "XServerGo",
				Username: "DefaultUser",
			},
		},
		{
			name: "custom secret",
			totp: &TOTP{
				Secret: "abcdefghijklmnop",
			},
			expected: &TOTP{
				Secret:   "ABCDEFGHIJKLMNOP",
				Interval: 30,
				Issuer:   "XServerGo",
				Username: "DefaultUser",
			},
		},
		{
			name: "custom issuer and username",
			totp: &TOTP{
				Issuer:   "TestIssuer",
				Username: "TestUser",
			},
			expected: &TOTP{
				Interval: 30,
				Issuer:   "TestIssuer",
				Username: "TestUser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.totp.checkAndRepair()
			if err != nil {
				t.Fatalf("checkAndRepair() error = %v", err)
			}

			if tt.totp.Interval != tt.expected.Interval {
				t.Errorf("Interval = %v, expected %v", tt.totp.Interval, tt.expected.Interval)
			}

			if tt.totp.Issuer != tt.expected.Issuer {
				t.Errorf("Issuer = %v, expected %v", tt.totp.Issuer, tt.expected.Issuer)
			}

			if tt.totp.Username != tt.expected.Username {
				t.Errorf("Username = %v, expected %v", tt.totp.Username, tt.expected.Username)
			}

			// 如果期望的Secret不为空，检查是否相等
			if tt.expected.Secret != "" {
				if tt.totp.Secret != tt.expected.Secret {
					t.Errorf("Secret = %v, expected %v", tt.totp.Secret, tt.expected.Secret)
				}
			} else {
				// 如果期望的Secret为空，检查是否生成了有效的Secret
				if tt.totp.Secret == "" {
					t.Error("Secret should not be empty after checkAndRepair")
				}
				if len(tt.totp.Secret) != 16 {
					t.Errorf("Secret length = %v, expected 16", len(tt.totp.Secret))
				}
			}
		})
	}
}

func TestTOTP_GetTOTPToken(t *testing.T) {
	tests := []struct {
		name    string
		totp    *TOTP
		wantErr bool
	}{
		{
			name: "valid secret",
			totp: &TOTP{
				Secret: "JBSWY3DPEHPK3PXP",
			},
			wantErr: false,
		},
		{
			name:    "empty secret should generate one",
			totp:    &TOTP{},
			wantErr: false,
		},
		{
			name: "invalid base32 secret",
			totp: &TOTP{
				Secret: "INVALID123456789",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.totp.GetTOTPToken()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTOTPToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(token) != 6 {
					t.Errorf("Token length = %v, expected 6", len(token))
				}
				// 验证token是否只包含数字
				matched, _ := regexp.MatchString("^[0-9]{6}$", token)
				if !matched {
					t.Errorf("Token should contain only 6 digits, got %v", token)
				}
			}
		})
	}
}

func TestTOTP_VerifyToken(t *testing.T) {
	totp := &TOTP{
		Secret: "JBSWY3DPEHPK3PXP",
	}

	// 获取当前token
	currentToken, err := totp.GetTOTPToken()
	if err != nil {
		t.Fatalf("Failed to get current token: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		want    bool
		wantErr bool
	}{
		{
			name:    "valid token",
			token:   currentToken,
			want:    true,
			wantErr: false,
		},
		{
			name:    "invalid token",
			token:   "000000",
			want:    false,
			wantErr: false,
		},
		{
			name:    "empty token",
			token:   "",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := totp.VerifyToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTOTP_GenerateQRCodeURL(t *testing.T) {
	tests := []struct {
		name    string
		totp    *TOTP
		wantErr bool
	}{
		{
			name: "complete TOTP",
			totp: &TOTP{
				Secret:   "JBSWY3DPEHPK3PXP",
				Interval: 30,
				Issuer:   "TestIssuer",
				Username: "TestUser",
			},
			wantErr: false,
		},
		{
			name:    "empty TOTP should use defaults",
			totp:    &TOTP{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := tt.totp.GenerateQRCodeURL()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateQRCodeURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// 验证URL格式
				if !strings.HasPrefix(url, "otpauth://totp/") {
					t.Errorf("URL should start with 'otpauth://totp/', got %v", url)
				}
				if !strings.Contains(url, "secret=") {
					t.Error("URL should contain 'secret=' parameter")
				}
				if !strings.Contains(url, "issuer=") {
					t.Error("URL should contain 'issuer=' parameter")
				}
				if !strings.Contains(url, "period=") {
					t.Error("URL should contain 'period=' parameter")
				}
			}
		})
	}
}

func TestGenerateRandomBase32Secret(t *testing.T) {
	secret1, err := generateRandomBase32Secret()
	if err != nil {
		t.Fatalf("generateRandomBase32Secret() error = %v", err)
	}

	secret2, err := generateRandomBase32Secret()
	if err != nil {
		t.Fatalf("generateRandomBase32Secret() error = %v", err)
	}

	// 验证secret长度
	if len(secret1) != 16 {
		t.Errorf("Secret length = %v, expected 16", len(secret1))
	}

	// 验证两次生成的secret不相同
	if secret1 == secret2 {
		t.Error("Two generated secrets should be different")
	}

	// 验证secret是有效的Base32字符串
	_, err = base32.StdEncoding.DecodeString(secret1)
	if err != nil {
		t.Errorf("Generated secret is not valid Base32: %v", err)
	}

	// 验证secret只包含有效的Base32字符
	validBase32 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for _, char := range secret1 {
		if !strings.Contains(validBase32, string(char)) {
			t.Errorf("Secret contains invalid Base32 character: %v", char)
		}
	}
}

func TestTOTP_Integration(t *testing.T) {
	// 集成测试：创建TOTP实例，生成token，验证token
	totp := &TOTP{
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
		Issuer:   "TestApp",
		Username: "testuser",
	}

	// 生成token
	token, err := totp.GetTOTPToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 验证token
	valid, err := totp.VerifyToken(token)
	if err != nil {
		t.Fatalf("Failed to verify token: %v", err)
	}

	if !valid {
		t.Error("Token should be valid")
	}

	// 生成QR码URL
	url, err := totp.GenerateQRCodeURL()
	if err != nil {
		t.Fatalf("Failed to generate QR code URL: %v", err)
	}

	expectedURL := "otpauth://totp/TestApp:testuser?secret=JBSWY3DPEHPK3PXP&issuer=TestApp&period=30"
	if url != expectedURL {
		t.Errorf("QR code URL = %v, expected %v", url, expectedURL)
	}
}

func TestTOTP_TimeBasedConsistency(t *testing.T) {
	// 测试在同一时间窗口内生成的token应该相同
	totp := &TOTP{
		Secret:   "JBSWY3DPEHPK3PXP",
		Interval: 30,
	}

	token1, err := totp.GetTOTPToken()
	if err != nil {
		t.Fatalf("Failed to generate first token: %v", err)
	}

	// 短暂等待，但仍在同一时间窗口内
	time.Sleep(100 * time.Millisecond)

	token2, err := totp.GetTOTPToken()
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	if token1 != token2 {
		t.Errorf("Tokens should be the same within the same time window: %v != %v", token1, token2)
	}
}

func BenchmarkTOTP_GetTOTPToken(b *testing.B) {
	totp := &TOTP{
		Secret: "JBSWY3DPEHPK3PXP",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := totp.GetTOTPToken()
		if err != nil {
			b.Fatalf("GetTOTPToken() error = %v", err)
		}
	}
}

func BenchmarkTOTP_VerifyToken(b *testing.B) {
	totp := &TOTP{
		Secret: "JBSWY3DPEHPK3PXP",
	}

	token, err := totp.GetTOTPToken()
	if err != nil {
		b.Fatalf("Failed to get token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := totp.VerifyToken(token)
		if err != nil {
			b.Fatalf("VerifyToken() error = %v", err)
		}
	}
}
