package urds

import (
	"github.com/123508/xservergo/pkg/util/id"
)

// 环境前缀,如:"dev","prod","test"
const (
	DevEnv  = "dev"  //开发环境
	ProdEnv = "prod" //生产环境
	TestEnv = "test" //测试环境
)

const (
	UserService = "user" //用户服务
	AuthService = "auth" //权限服务
	FileService = "file" //文件服务
)

type Keys interface {
	SetEnvPrefix(env string)
	GetEnvPrefix() string
	RequestIdKey(requestId string) string
}

type CommonKeys struct {
	env     string
	service string
}

func NewCommonKeys(string string, serviceName string) *CommonKeys {
	return &CommonKeys{env: string, service: serviceName}
}

func (ck *CommonKeys) SetEnvPrefix(env string) {
	ck.env = env
}

func (ck *CommonKeys) GetEnvPrefix() string {
	return ck.env
}
func (ck *CommonKeys) GetService() string {
	return ck.service
}

func (u CommonKeys) BlackRefreshTokenKey(refreshToken string) string {
	return TakeKey(u.GetEnvPrefix(), "refresh_token", refreshToken)
}

func (u CommonKeys) BlackAccessTokenKey(accessToken string) string {
	return TakeKey(u.GetEnvPrefix(), "access_token", accessToken)
}

func (u CommonKeys) RequestIdKey(requestId string) string {
	return TakeKey(u.GetEnvPrefix(), "request_id", requestId)
}

// 用户服务缓存
type UserKeys struct {
	*CommonKeys
}

func NewUserKeys(env string) *UserKeys {
	return &UserKeys{
		NewCommonKeys(env, UserService),
	}
}

func (u UserKeys) SmsLoginKey(phone string) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "sms_login", phone)
}

func (u UserKeys) SmsVCodeKey(phone string) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "sms_login_verify_code", phone)
}

func (u UserKeys) QrLoginKey(uniqueSign string) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "qr_login", uniqueSign)
}

func (u UserKeys) QrStoreUidKey(ticket string) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "qr_store_uid", ticket)
}

func (u UserKeys) DetailUserInfoKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "detail", "id", uid)
}

func (u UserKeys) DetailUserInfoSignKey(typical string, sign string) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "detail", typical, sign)
}

func (u UserKeys) ForgetPwdKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "forget_pwd", uid)
}

func (u UserKeys) VersionKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "version", uid)
}

func (u UserKeys) DeactivateKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "deactivate", uid)
}

func (u UserKeys) DeleteKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "delete", uid)
}

func (u UserKeys) BindEmailKey(sign string, uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "bind_email", sign, uid)
}

func (u UserKeys) BindPhoneKey(sign string, uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "bind_phone", sign, uid)
}

func (u UserKeys) ChangePhone1Key(sign string, uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_phone1", sign, uid)
}

func (u UserKeys) ChangePhone2Key(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_phone2", uid)
}

func (u UserKeys) StorePhoneKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_new_phone", uid)
}

func (u UserKeys) ChangeEmail1Key(sign string, uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_email1", sign, uid)
}

func (u UserKeys) ChangeEmail2Key(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_email2", uid)
}

func (u UserKeys) StoreEmailKey(uid id.UUID) string {
	return TakeKey(u.GetEnvPrefix(), u.GetService(), "change_new_email", uid)
}

// 权限服务缓存
type AuthKeys struct {
	*CommonKeys
}

func NewAuthKeys(env string) *AuthKeys {
	return &AuthKeys{
		CommonKeys: NewCommonKeys(env, AuthService),
	}
}

// 文件服务缓存
type FileKeys struct {
	*CommonKeys
}

func NewFileKeys(env string) *FileKeys {
	return &FileKeys{
		CommonKeys: NewCommonKeys(env, FileService),
	}
}

func (f FileKeys) FileIDKey(fileID id.UUID) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "file_id", fileID)
}

func (f FileKeys) FIleMd5AndNameAndSizeKey(fileMd5, fileName string, fileSize uint64) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "file_md5_name_size", fileMd5, fileName, fileSize)
}

func (f FileKeys) FileListKeyWithFunc(userId id.UUID, funcName string) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "file_list", userId, funcName)
}

func (f FileKeys) DetailFileQueryKey() string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "detail_file_query")
}

func (f FileKeys) ChunkKey(path string) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "chunk", path)
}

func (f FileKeys) UploadIdKey(uploadId string) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "upload_id", uploadId)
}

func (f FileKeys) FileChunkTotalKey(fileId id.UUID) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "file_chunk_total", fileId)
}

func (f FileKeys) FileChunkStoreTypeKey(fileId id.UUID) string {
	return TakeKey(f.GetEnvPrefix(), f.GetService(), "file_chunk_type", fileId)
}
