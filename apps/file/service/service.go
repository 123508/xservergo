package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/123508/xservergo/pkg/util/urds"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type FileService interface {
	GetRedis() *redis.Client
	InitFileUpload(ctx context.Context, fileList []models.File, targetUserId, requestUserId id.UUID) (existingFileMd5s []models.File, requestId string, err error)
}

type ServiceImpl struct {
	DB      *gorm.DB
	Rds     *redis.Client
	Version int
	Keys    *urds.FileKeys
}

func NewService(database *gorm.DB, rds *redis.Client, env string) FileService {
	return &ServiceImpl{
		DB:      database,
		Rds:     rds,
		Version: 1,
		Keys:    urds.NewFileKeys(env),
	}
}

func (s *ServiceImpl) GetRedis() *redis.Client {
	return s.Rds
}

func (s *ServiceImpl) GetDB() *gorm.DB {
	return s.DB
}

// InitFileUpload 采用乐观策略,只要有已经存在的文件就可以关联
func (s *ServiceImpl) InitFileUpload(ctx context.Context, fileList []models.File, targetUserId, requestUserId id.UUID) (existingFileMd5s []models.File, requestId string, err error) {

	if len(fileList) > 500 {
		return nil, "", cerrors.NewCommonError(http.StatusBadRequest, "请求文件过多,请减少个数", "", nil)
	}

	// 获取响应requestId
	requestId, err = urds.GenerateRequestId(s.Rds, s.Keys, ctx, 4*60*time.Minute)
	if err != nil {
		return nil, "", err
	}

	//获取已经存在的文件
	existingFiles, err := s.GetExistingFiles(ctx, fileList, targetUserId)

	if err != nil {
		return nil, "", err
	}

	//关联用户和文件
	err = s.RelateUserWithFiles(ctx, targetUserId, existingFiles)

	if err != nil {
		return nil, "", err
	}

	// 将fileList中已经关联过的文件去除
	existingMap := make(map[id.UUID]models.File)
	for _, file := range existingFiles {
		existingMap[file.ID] = file
	}
	unexistingList := make([]models.File, 0)
	for _, file := range fileList {
		if _, ok := existingMap[file.ID]; !ok {
			unexistingList = append(unexistingList, file)
		}
	}

	//临时路径创建
	for _, item := range unexistingList {
		path := "../../store/" + item.FileMd5 + "/" + item.FilePath
		dirErr := s.SafeCreateDir(path)
		if dirErr != nil {
			return nil, "", err
		}
	}

	return existingFiles, requestId, nil
}

// GetExistingFiles 获取已经存在的文件
func (s *ServiceImpl) GetExistingFiles(ctx context.Context, fileList []models.File, userId id.UUID) ([]models.File, error) {

	if len(fileList) == 0 {
		return []models.File{}, nil
	}

	// 带缓存的组件查询
	query := urds.ListCacheComponent[id.UUID, models.File]{
		Rds:             s.Rds,
		Ctx:             ctx,
		ListKey:         s.Keys.FileListKeyWithFunc(userId, "GetExistingFiles"),
		DetailKeyPrefix: s.Keys.DetailFileQueryKey(),
		Marshal:         json.Marshal,
		Unmarshal:       json.Unmarshal,
		FullQueryExec: func() ([]models.File, error) { // 全量查询
			existingFiles := make([]models.File, 0)
			// 构建一个查询条件，一次性查询所有(MD5，文件名)组合
			conditions := make([]string, 0)
			args := make([]interface{}, 0)
			for _, item := range fileList {
				conditions = append(conditions, "(file_md5 = ? and file_name = ?)")
				args = append(args, item.FileMd5, item.FileName)
			}
			whereClause := strings.Join(conditions, " or ")

			// 在数据库层面执行联合查询
			err := s.DB.WithContext(ctx).Model(&models.File{}).
				Where(whereClause, args...).
				Find(&existingFiles).Error

			if err != nil {
				logs.ErrorLogger.Error("获取已有文件错误", zap.Error(err))
				return nil, cerrors.NewSQLError(http.StatusInternalServerError, "获取已有文件错误", err)
			}

			return existingFiles, nil
		},
		PartQueryExec: func(fails []id.UUID) ([]models.File, error) { //分量查询
			existingFiles := make([]models.File, 0)
			conditions := make([]string, 0)
			args := make([]interface{}, 0)
			for _, item := range fails {
				conditions = append(conditions, "(id = ?)")
				args = append(args, item)
			}
			whereClause := strings.Join(conditions, " or ")

			// 在数据库层面执行联合查询
			err := s.DB.WithContext(ctx).Model(&models.File{}).
				Where(whereClause, args...).
				Find(&existingFiles).Error

			if err != nil {
				logs.ErrorLogger.Error("获取已有文件错误", zap.Error(err))
				return nil, cerrors.NewSQLError(http.StatusInternalServerError, "获取已有文件错误", err)
			}

			return existingFiles, nil
		},
		Expires:     10 * time.Minute,
		Random:      2 * time.Minute,
		MaxLostRate: 30,
		Sort: func(files []models.File) []models.File {
			return files
		},
	}

	existingFiles, err := query.QueryListWithCache()

	if err != nil {
		return nil, err
	}

	return existingFiles, nil
}

// RelateUserWithFiles 将已经存在的文件和用户关联
func (s *ServiceImpl) RelateUserWithFiles(ctx context.Context, userId id.UUID, fileList []models.File) error {

	if len(fileList) == 0 {
		return nil
	}

	// 正确初始化一个空切片
	fileID := make([]id.UUID, 0, len(fileList)) // 使用cap预分配，避免多次扩容
	fileUserLists := make([]models.FileUser, 0, len(fileList))

	for _, file := range fileList {
		fileUserLists = append(fileUserLists, models.FileUser{
			UserId: userId,
			FileId: file.ID,
		})
		fileID = append(fileID, file.ID)
	}

	query := urds.ListCacheComponent[id.UUID, models.FileUser]{
		Rds:             s.Rds,
		Ctx:             ctx,
		ListKey:         s.Keys.FileListKeyWithFunc(userId, "RelateUserWithFiles"),
		DetailKeyPrefix: "",
		Marshal:         json.Marshal,
		Unmarshal:       json.Unmarshal,
		FullQueryExec: func() ([]models.FileUser, error) {

			existing := make([]models.FileUser, 0)
			conditions := make([]string, 0)
			args := make([]interface{}, 0)
			for _, item := range fileUserLists {
				conditions = append(conditions, "(user_id = ? and file_id = ?)")
				args = append(args, item.UserId, item.FileId)
			}
			whereClause := strings.Join(conditions, " or ")

			// 在数据库层面执行联合查询
			err := s.DB.WithContext(ctx).Model(&models.FileUser{}).
				Where(whereClause, args...).
				Find(&existing).Error

			if err != nil {
				logs.ErrorLogger.Error("获取已有用户关联文件错误", zap.Error(err))
				return nil, cerrors.NewSQLError(http.StatusInternalServerError, "获取已有用户关联文件错误", err)
			}

			return existing, nil

		},
		PartQueryExec: func(fails []id.UUID) ([]models.FileUser, error) {

			existing := make([]models.FileUser, 0)
			conditions := make([]string, 0)
			args := make([]interface{}, 0)
			for _, item := range fails {
				conditions = append(conditions, "(id = ?)")
				args = append(args, item)
			}
			whereClause := strings.Join(conditions, " or ")

			// 在数据库层面执行联合查询
			err := s.DB.WithContext(ctx).Model(&models.FileUser{}).
				Where(whereClause, args...).
				Find(&existing).Error

			if err != nil {
				logs.ErrorLogger.Error("获取已有用户关联文件错误", zap.Error(err))
				return nil, cerrors.NewSQLError(http.StatusInternalServerError, "获取已有用户关联文件错误", err)
			}

			return existing, nil
		},
		Expires:     10 * time.Minute,
		Random:      2 * time.Minute,
		MaxLostRate: 30,
		Sort: func(users []models.FileUser) []models.FileUser {
			return users
		},
	}

	relateFileUserLists, err := query.QueryListWithCache()

	if err != nil {
		return err
	}

	relateFileUserMap := make(map[id.UUID]models.FileUser)

	for _, item := range relateFileUserLists {
		relateFileUserMap[item.ID] = item
	}

	unrelateFileUserList := make([]models.FileUser, 0)
	unrelateFileID := make([]id.UUID, 0)

	for _, item := range fileUserLists {
		if _, ok := relateFileUserMap[item.ID]; !ok {
			unrelateFileUserList = append(unrelateFileUserList, item)
			unrelateFileID = append(unrelateFileID, item.ID)
		}
	}

	fileID = unrelateFileID
	fileUserLists = unrelateFileUserList

	// 开始事务，并指定上下文
	tx := s.DB.Begin().WithContext(ctx)
	if tx.Error != nil {
		return cerrors.NewSQLError(http.StatusInternalServerError, "开启事务失败", tx.Error)
	}

	// 使用defer，并根据最终错误状态决定提交或回滚
	defer func() {
		if r := recover(); r != nil {
			// 处理panic，优先回滚事务
			tx.Rollback()
			// 可以将panic转换为错误抛出，或记录日志，这里根据你的项目规范处理
			logs.ErrorLogger.Error("事务执行发生panic", zap.Any("panic", r))
			panic(r) // 重新抛出panic，或者选择返回错误
		} else if err != nil {
			// 函数因错误返回，回滚事务
			tx.Rollback()
		} else {
			// 没有错误，提交事务
			err = tx.Commit().Error
			if err != nil {
				logs.ErrorLogger.Error("提交事务失败", zap.Error(err))
				// 注意：此时err已被赋值，函数将返回此错误
			}
		}
	}()

	// 执行批量插入
	err = tx.Model(&models.FileUser{}).Create(&fileUserLists).Error
	if err != nil {
		logs.ErrorLogger.Error("插入文件-用户关联数据错误", zap.Error(err))
		return cerrors.NewSQLError(http.StatusInternalServerError, "插入数据错误", err)
		// 返回err后，defer中的逻辑会检测到err非空，从而执行回滚
	}

	// 更新文件引用计数
	err = tx.Model(&models.File{}).Exec("update file set count = count + 1 where id in (?)", fileID).Error
	if err != nil {
		logs.ErrorLogger.Error("更新文件引用计数错误", zap.Error(err))
		return cerrors.NewSQLError(http.StatusInternalServerError, "更新引用错误", err)
		// 返回err后，defer中的逻辑会检测到err非空，从而执行回滚
	}

	// 如果执行到这里，说明所有操作成功。
	// defer 中的逻辑会检测到 err 为 nil，从而执行 tx.Commit()
	return nil
}

// SafeCreateDir 确保目录存在，如果不存在则创建它(多级创建)
func (s *ServiceImpl) SafeCreateDir(dirPath string) error {
	// 1. 检查路径是否存在
	_, err := os.Stat(dirPath)

	if err == nil { // 错误为nil，说明文件或目录已存在
		return nil
	}

	// 2. 如果错误是因为目录不存在，则创建它
	if os.IsNotExist(err) { // 使用 MkdirAll 递归创建目录
		err = os.MkdirAll(dirPath, 0755)
		if err != nil {
			return cerrors.NewCommonError(http.StatusInternalServerError, "创建目录失败", "", fmt.Errorf("创建目录失败: %w", err))
		}
		return nil
	}

	// 3. 如果是其他错误，直接返回
	return cerrors.NewCommonError(http.StatusInternalServerError, "检查路径时发生未知错误", "", fmt.Errorf("检查路径时发生未知错误: %w", err))
}

// CreateFileWithDir 在指定的多级目录下安全创建文件。
func (s *ServiceImpl) CreateFileWithDir(fullFilePath string) error {
	// 1. 提取文件所在的目录路径
	dirPath := filepath.Dir(fullFilePath)

	// 2. 使用 os.MkdirAll 递归创建所有需要的目录，权限设置为 0755
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err // 处理目录创建错误，如权限不足、磁盘满等
	}

	// 3. 目录已确保存在，调用 SafeCreateFile 来安全创建文件
	err = s.safeCreateFile(fullFilePath)
	if err != nil {
		return err // 处理文件创建错误
	}

	return nil
}

// SafeCreateFile 确保文件存在，如果不存在则创建它
func (s *ServiceImpl) safeCreateFile(filename string) error {

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		if errors.Is(err, os.ErrExist) { // 文件已存在，符合预期，不做任何处理，直接返回 nil
			return nil
		}
		// 其他错误（如权限不足、磁盘满、路径不存在等），直接返回给调用方
		return cerrors.NewCommonError(http.StatusInternalServerError, "创建文件失败", "", err)
	}
	// 使用 defer 确保文件句柄被关闭，释放系统资源，这是关键的最佳实践[1](@ref)
	defer file.Close()

	// 文件创建成功
	return nil
}
