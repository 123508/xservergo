package repo

import (
	"context"
	"errors"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserRepository interface {
	GetDB() *gorm.DB
	CreateUser(ctx context.Context, user *models.User, uLogin *models.UserLogin) error
	ComparePassword(ctx context.Context, userID util.UUID, password string) (bool, error)
	GetUserByID(ctx context.Context, userID util.UUID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) (int, error)
	DeleteUser(ctx context.Context, userID util.UUID) error
	ListUsers(ctx context.Context, page, pageSize int, filterSql string, filterParams []interface{}, sortSql []string) ([]models.User, error)
	UpdatePassword(ctx context.Context, userID util.UUID, password string) error
	RemoveEmail(ctx context.Context, userID util.UUID, version int) (int, error)
	SetEmail(ctx context.Context, userID util.UUID, email string, version int) (int, error)
	FreezeUser(ctx context.Context, userID util.UUID, version int) (int, error)
	UnfreezeUser(ctx context.Context, userID util.UUID, version int) (int, error)
}

type RepoImpl struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &RepoImpl{
		DB: db,
	}
}

func (r *RepoImpl) GetDB() *gorm.DB {
	return r.DB
}

func (r *RepoImpl) CreateUser(ctx context.Context, user *models.User, uLogin *models.UserLogin) error {

	if user == nil || uLogin == nil {
		return errors.New("不允许用户或用户密码为空")
	}

	err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		//创建用户对象
		insertUserStmt := `insert into 
    tiktok.users(id, username, nickname, email, phone, gender, avatar, status, created_at, version,deleted_at) 
		values (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,null)`

		if err := tx.Exec(insertUserStmt, user.ID, user.UserName, user.NickName,
			user.Email, user.Phone, user.Gender, user.Avatar, user.Status, user.AuditFields.Version).Error; err != nil {
			return err
		}

		//创建用户
		insertULoginStmt := `insert into 
    tiktok.user_login(user_id, password, created_at, version,deleted_at) 
		values (?,?,current_timestamp,?,null)`

		if err := tx.Exec(insertULoginStmt, user.ID, uLogin.Password, uLogin.AuditFields.Version).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		logs.ErrorLogger.Error("创建用户对象错误", zap.Error(err))
		return err
	}

	return nil
}

func (r *RepoImpl) ComparePassword(ctx context.Context, userID util.UUID, password string) (bool, error) {
	var res int

	compStmt := `select exists(
  select 1 from tiktok.user_login 
  where user_id = ? and password = ? and is_deleted = 0
)`

	if err := r.DB.WithContext(ctx).Raw(compStmt, userID, password).Scan(&res).Error; err != nil {
		logs.ErrorLogger.Error("查询用户密码错误", zap.Error(err))
		return false, err
	}
	return res != 0, nil
}

func (r *RepoImpl) GetUserByID(ctx context.Context, userID util.UUID) (*models.User, error) {

	var row models.User

	queryStmt := `select 
    id, username, nickname, email, phone, gender, avatar, status, created_at,updated_at,version
from tiktok.users where id = ? and is_deleted = 0 limit 1`

	if err := r.DB.WithContext(ctx).Raw(queryStmt, userID).Scan(&row).Error; err != nil {
		logs.ErrorLogger.Error("通过id获取用户信息", zap.Error(err))
		return nil, err
	}

	return &row, nil
}

func (r *RepoImpl) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	//从users表中读取Email信息
	var row models.User

	queryStmt := `select 
    id, username, nickname, email, phone, gender, avatar, status, created_at,updated_at,version
		from tiktok.users where email = ? and is_deleted = 0 limit 1`

	if err := r.DB.WithContext(ctx).Raw(queryStmt, email).Scan(&row).Error; err != nil {
		logs.ErrorLogger.Error("通过email获取用户信息", zap.Error(err))
		return nil, err
	}

	return &row, nil
}

func (r *RepoImpl) UpdateUser(ctx context.Context, u *models.User) (int, error) {
	// 1. 构建更新字段Map
	updates := make(map[string]interface{})

	// 基础字段（总是更新）
	updates["gender"] = u.Gender

	// 可选字段（空值不更新）
	if u.Phone != "" {
		updates["phone"] = u.Phone
	}
	if u.NickName != "" {
		updates["nickname"] = u.NickName // 修正字段名
	}
	if u.Avatar != "" {
		updates["avatar"] = u.Avatar
	}

	// 乐观锁控制
	updates["version"] = gorm.Expr("version + 1") // 使用表达式确保原子性

	// 2. 执行更新（带乐观锁检查）
	result := r.DB.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND version = ? AND deleted_at IS NULL", u.ID, u.AuditFields.Version).
		Updates(updates)

	if result.Error != nil {
		logs.ErrorLogger.Error("更新用户出错",
			zap.Error(result.Error),
			zap.ByteString("userID", u.ID[:]),
			zap.Int("version", u.Version))
		return u.Version, result.Error
	}

	// 3. 检查乐观锁冲突
	if result.RowsAffected == 0 {
		err := errors.New("更新失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(),
			zap.ByteString("userID", u.ID[:]),
			zap.Int("expected_version", u.Version))
		return u.Version, err
	}

	// 4. 获取新版本号（避免额外查询）
	return u.Version + 1, nil
}

func (r *RepoImpl) DeleteUser(ctx context.Context, UserID util.UUID) error {

	err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		delUserStmt := `update tiktok.users set deleted_at = CURRENT_TIMESTAMP where id = ? and is_deleted = 0`

		if err := tx.Exec(delUserStmt, UserID).Error; err != nil {
			return err
		}

		delULoginStmt := `update tiktok.user_login set deleted_at = CURRENT_TIMESTAMP where user_id = ? and is_deleted = 0`

		if err := tx.Exec(delULoginStmt, UserID).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		logs.ErrorLogger.Error("删除用户异常", zap.Error(err))
		return err
	}
	return nil
}

func (r *RepoImpl) ListUsers(ctx context.Context,
	page, pageSize int, filterSql string, filterParams []interface{}, sortSql []string) ([]models.User, error) {

	tx := r.DB.WithContext(ctx).Model(&models.User{}).Where("is_deleted = 0").Where(filterSql, filterParams...)

	for _, v := range sortSql {
		tx = tx.Order(v)
	}

	tx = tx.Offset((page - 1) * pageSize).Limit(pageSize)

	var users []models.User
	if err := tx.Find(&users).Error; err != nil {
		logs.ErrorLogger.Error("查询用户列表失败", zap.Error(err))
		return nil, err
	}
	return users, nil
}

func (r *RepoImpl) UpdatePassword(ctx context.Context, userID util.UUID, password string) error {

	updateStmt := `update tiktok.user_login 
set password = ? , updated_at = CURRENT_TIMESTAMP , version = version+1
                                        where user_id = ? and is_deleted = 0`

	result := r.DB.WithContext(ctx).Exec(updateStmt, password, userID)

	if err := result.Error; err != nil {
		logs.ErrorLogger.Error("更新用户密码错误", zap.Error(err))
		return err
	}

	// 检查是否成功更新
	if result.RowsAffected == 0 {
		err := errors.New("更新密码失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(), zap.ByteString("userID", userID[:]))
		return err
	}

	return nil
}

func (r *RepoImpl) RemoveEmail(ctx context.Context, userID util.UUID, version int) (int, error) {

	removeStmt := `update tiktok.users 
						set email = '', version =version+1 , updated_at = CURRENT_TIMESTAMP
						where id = ? and version = ? and is_deleted = 0`

	result := r.DB.WithContext(ctx).Exec(removeStmt, userID, version)

	if err := result.Error; err != nil {
		logs.ErrorLogger.Error("解绑邮箱失败", zap.Error(err))
		return version, err
	}

	// 检查是否成功更新
	if result.RowsAffected == 0 {
		err := errors.New("解绑邮箱失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(), zap.ByteString("userID", userID[:]))
		return version, err
	}

	return version + 1, nil
}

func (r *RepoImpl) SetEmail(ctx context.Context, userID util.UUID, email string, version int) (int, error) {

	setStmt := `update tiktok.users 
						set email = ? , version =version+1 , updated_at = CURRENT_TIMESTAMP
						where id = ? and version = ? and is_deleted = 0`

	result := r.DB.WithContext(ctx).Exec(setStmt, email, userID, version)

	if err := result.Error; err != nil {
		logs.ErrorLogger.Error("绑定邮箱失败", zap.Error(err))
		return version, err
	}

	// 检查是否成功更新
	if result.RowsAffected == 0 {
		err := errors.New("绑定邮箱失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(), zap.ByteString("userID", userID[:]))
		return version, err
	}

	return version + 1, nil
}

func (r *RepoImpl) FreezeUser(ctx context.Context, userID util.UUID, version int) (int, error) {

	freezeStmt := `update tiktok.users 
						set status = 1 , version = version+1 , updated_at = CURRENT_TIMESTAMP
 						where id = ? and version = ? and is_deleted = 0`

	result := r.DB.WithContext(ctx).Exec(freezeStmt, userID, version)

	if result.Error != nil {
		logs.ErrorLogger.Error("冻结用户失败", zap.Error(result.Error))
		return version, result.Error
	}

	// 检查是否成功更新
	if result.RowsAffected == 0 {
		err := errors.New("冻结失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(), zap.ByteString("userID", userID[:]))
		return version, err
	}

	return version + 1, nil
}

func (r *RepoImpl) UnfreezeUser(ctx context.Context, userID util.UUID, version int) (int, error) {

	unFreezeStmt := `update tiktok.users 
						set status = 0 , version = version+1 , updated_at = CURRENT_TIMESTAMP
 						where id = ? and version = ? and is_deleted = 0`

	result := r.DB.WithContext(ctx).Exec(unFreezeStmt, userID, version)

	if result.Error != nil {
		logs.ErrorLogger.Error("解冻用户失败", zap.Error(result.Error))
		return version, result.Error
	}

	// 检查是否成功更新
	if result.RowsAffected == 0 {
		err := errors.New("解冻失败：用户不存在或版本不匹配")
		logs.ErrorLogger.Error(err.Error(), zap.ByteString("userID", userID[:]))
		return version, err
	}

	return version + 1, nil
}
