package user

type AccountLog struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type EmailLog struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type PhoneLog struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type RegisterModel struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Gender   uint64 `json:"gender"`
}

type SmsLog struct {
	Phone     string `json:"phone"`
	Code      string `json:"code"`
	Flow      int32  `json:"flow"`
	RequestId string `json:"request_id"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type DeviceSign struct {
	ClientIp  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`
}

type QrQuery struct {
	Ticket    string `json:"ticket"`
	Timeout   uint64 `json:"timeout"`
	RequestId string `json:"request_id"`
}

type QrLog struct {
	Ticket    string `json:"ticket"`
	Timeout   uint64 `json:"timeout"`
	RequestId string `json:"request_id"`
	UserId    string `json:"user_id"`
}

type QrMobileReq struct {
	Ticket    string `json:"ticket"`
	RequestId string `json:"request_id"`
}

type ChangePwd struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	UserId      string `json:"user_id"`
}

type ForgetPwd struct {
	Phone    string `json:"phone"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Type     uint64 `json:"type"`
}

type ResetPwd struct {
	NewPassword  string `json:"new_password"`
	TargetUserId string `json:"target_user_id"`
	VerifyCode   string `json:"verify_code"`
	RequestId    string `json:"request_id"`
}

type UStruct struct {
	UserId   string `json:"user_id"`
	Phone    string `json:"phone"`
	Email    string `json:"email"`
	Username string `json:"username"`
}
