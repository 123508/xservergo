package service

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/config"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/123508/xservergo/pkg/util/toMd5"
	"github.com/123508/xservergo/pkg/util/urds"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type FileService interface {
	GetRedis() *redis.Client
	InitFileUpload(ctx context.Context, fileList []models.File, targetUserId, requestUserId id.UUID) (files []models.File, uploadId, requestId string, err error)
	UploadChunk(ctx context.Context, fileId id.UUID, chunkIndex uint64, uploadId string, content []byte, chunkContentHash string, requestId string, targetUserId, requestUserId id.UUID) (bool, string, error)
	UploadVerify(ctx context.Context, fileIds []id.UUID, requestId, uploadId string, targetUserId, requestUserId id.UUID) (files []VerifyFile, err error)
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

func (s *ServiceImpl) InitFileUpload(ctx context.Context, fileList []models.File, targetUserId, requestUserId id.UUID) (files []models.File, uploadId, requestId string, err error) {

	// 限制文件数量
	if len(fileList) > 500 {
		return nil, "", "", cerrors.NewCommonError(http.StatusBadRequest, "请求文件过多,请减少个数", "", nil)
	}

	// 获取requestId
	requestId, err = urds.GenerateRequestId(s.Rds, s.Keys, ctx, 24*60*time.Minute)
	if err != nil {
		return nil, "", "", err
	}

	// 获取uploadId
	uploadId, err = urds.GenerateUploadId(s.Rds, s.Keys, ctx, 24*60*time.Minute)
	if err != nil {
		return nil, "", "", err
	}

	needs := make([]models.File, 0)

	for _, f := range fileList {
		file, err := s.InsertAndRelateFile(ctx, f, targetUserId)
		if err != nil {
			return nil, "", "", err
		}
		needs = append(needs, file)
	}

	return needs, uploadId, requestId, nil
}

func (s *ServiceImpl) InsertAndRelateFile(ctx context.Context, file models.File, userId id.UUID) (models.File, error) {

	var res models.File

	err := s.DB.WithContext(ctx).Model(&models.File{}).Where("file_hash = ?", file.FileHash).First(&res).Error //查询文件是否存在

	// 不存在就直接创建
	if res.FileHash == "" || res.ID.IsZero() {
		file.ID = id.NewUUID()
		file.Status = 1
		err := s.DB.Create(&file).Error
		if err != nil {
			logs.ErrorLogger.Error("创建文件错误", zap.Error(err))
			return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "创建文件错误", err)
		}
		res = file
	}

	// 校验文件是否被关联
	var count int64 = 0
	s.DB.Model(&models.FileUser{}).Where("file_id = ? and user_id = ?", res.ID, userId).Count(&count)
	if count > 0 {
		return res, nil
	}

	tx := s.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	// 将文件的计数加一
	fileSql := `update file set count = count + 1 where id = ?`
	err = tx.Exec(fileSql, res.ID).Error
	if err != nil {
		logs.ErrorLogger.Error("更新错误", zap.Error(err))
		return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新错误", err)
	}

	//关联用户和文件
	contract := models.FileUser{
		ID:     id.NewUUID(),
		FileId: res.ID,
		UserId: userId,
	}
	err = tx.Create(&contract).Error
	if err != nil {
		logs.ErrorLogger.Error("更新错误", zap.Error(err))
		return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新错误", err)
	}

	tx.Commit()

	s.Rds.Set(ctx, s.Keys.FileChunkTotalKey(res.ID), res.Total, 10*time.Minute)

	return res, nil
}

func (s *ServiceImpl) UploadChunk(ctx context.Context, fileId id.UUID, chunkIndex uint64, uploadId string, content []byte, chunkHash string, requestId string, targetUserId, requestUserId id.UUID) (verify bool, requestID string, err error) {

	// 校验requestId
	err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("requestId过期", zap.String("requestId", requestId), zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
	}

	// 校验uploadId
	uploadRs := s.Rds.Get(ctx, s.Keys.UploadIdKey(uploadId)).String()
	if uploadRs == "" {
		logs.ErrorLogger.Error("uploadId过期", zap.String("uploadId", uploadId))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "上传id过期", requestId, nil)
	}
	s.Rds.Expire(ctx, s.Keys.UploadIdKey(uploadId), 24*60*time.Minute)

	// 文件内容hash校验
	hashData := toMd5.ContentToMd5(content)
	if chunkHash != hashData {
		logs.ErrorLogger.Error("分片数据校验失败,请重新传输", zap.String("requestId", requestId), zap.Uint64("chunkIndex", chunkIndex))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "分片数据错误", requestId, nil)
	}

	// 校验分片是否存在
	totalCount, err := s.Rds.Get(ctx, s.Keys.FileChunkTotalKey(fileId)).Uint64()
	if totalCount <= 0 && err != nil {

		fileExist := models.File{}
		s.DB.Model(&models.File{}).Where("id = ?", fileId).First(&fileExist)
		if fileExist.ID.IsZero() || fileExist.FileHash == "" {
			logs.ErrorLogger.Error("文件不存在,无法传输分片", zap.String("uploadId", uploadId))
			return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "文件不存在", requestId, nil)
		}

		s.Rds.Set(ctx, s.Keys.FileChunkTotalKey(fileId), fileExist.Total, 10*time.Minute)
	}

	if chunkIndex > totalCount || chunkIndex <= 0 {
		logs.ErrorLogger.Error("分片索引错误", zap.String("uploadId", uploadId))
		return false, "", cerrors.NewCommonError(http.StatusBadRequest, "分片索引错误", requestId, nil)
	}

	s.Rds.Expire(ctx, s.Keys.FileChunkTotalKey(fileId), 10*time.Minute)

	// 查询分片是否存在
	fileChunk := models.FileChunk{}
	s.DB.Model(&models.FileChunk{}).Where("chunk_hash = ?", chunkHash).First(&fileChunk)

	//分片存在
	if !fileChunk.ID.IsZero() && fileChunk.ChunkHash != "" {

		// 查询分片是否被关联
		var count int64 = 0
		s.DB.Model(&models.FileChunkIndex{}).Where("file_id = ? and chunk_id = ?", fileId, fileChunk.ID).Count(&count)

		// 未关联分片就直接关联
		if count == 0 {
			now := time.Now()

			fileChunkIndex := models.FileChunkIndex{
				FileID:     fileId,
				ChunkID:    fileChunk.ID,
				ChunkIndex: chunkIndex,
				CreatedAt:  &now,
			}

			if err := s.DB.Create(&fileChunkIndex).Error; err != nil {
				logs.ErrorLogger.Error("数据库记录分片序号错误", zap.Error(err))
				return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入记录失败", requestId, err)
			}
		}

		return true, requestId, nil
	}

	dirPath, _ := filepath.Abs(config.Conf.FileConfig.FileStorePosition)

	path := filepath.Join(dirPath, chunkHash)
	path = filepath.Clean(path)

	// 序列化写入文件
	os.MkdirAll(dirPath, 0755)
	file, err := os.Create(path)
	if err != nil {
		logs.ErrorLogger.Error("创建文件失败", zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "创建文件失败", requestId, err)
	}

	defer file.Close()

	// 写入文件内容
	if _, err = file.Write(content); err != nil {
		logs.ErrorLogger.Error("写入分片内容失败", zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入分片失败", requestId, err)
	}

	tx := s.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	now := time.Now()

	// 记录分片元数据到数据库
	chunk := models.FileChunk{
		ID:        id.NewUUID(),
		ChunkHash: chunkHash,
		ChunkName: path,
		CreatedAt: &now,
	}
	err = tx.Model(&models.FileChunk{}).Create(&chunk).Error
	if err != nil {
		logs.ErrorLogger.Error("数据库记录分片错误", zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入分片失败", requestId, err)
	}

	// 记录分片和文件的关系
	fileChunkIndex := models.FileChunkIndex{
		FileID:     fileId,
		ChunkID:    chunk.ID,
		ChunkIndex: chunkIndex,
		CreatedAt:  &now,
	}
	err = tx.Model(&models.FileChunkIndex{}).Create(&fileChunkIndex).Error
	if err != nil {
		logs.ErrorLogger.Error("数据库记录分片序号错误", zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入记录失败", requestId, err)
	}

	tx.Commit()

	return true, requestId, nil
}

func (s *ServiceImpl) UploadVerify(ctx context.Context, fileIds []id.UUID, requestId, uploadId string, targetUserId, requestUserId id.UUID) (files []VerifyFile, err error) {

	// 校验requestId
	err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("requestId过期", zap.String("requestId", requestId), zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
	}

	// 校验uploadId
	uploadRs := s.Rds.Get(ctx, s.Keys.UploadIdKey(uploadId)).String()
	if uploadRs == "" {
		logs.ErrorLogger.Error("uploadId过期", zap.String("uploadId", uploadId))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "上传id过期", requestId, nil)
	}
	s.Rds.Expire(ctx, s.Keys.UploadIdKey(uploadId), 24*60*time.Minute)

	// 验证文件并返回
	files = make([]VerifyFile, len(fileIds))

	for i, fileId := range fileIds {
		f, err := s.VerifyFile(ctx, fileId)
		if err != nil {
			return nil, err
		}
		files[i] = f
	}
	return files, nil
}

func (s *ServiceImpl) VerifyFile(ctx context.Context, fileId id.UUID) (VerifyFile, error) {

	// 校验文件是否存在
	f := models.File{}
	s.DB.Model(&models.File{}).Where("id = ?", fileId).First(&f)
	if f.ID.IsZero() || f.FileHash == "" {
		logs.ErrorLogger.Error("文件不存在", zap.String("fileId", fileId.MarshalBase64()))
		return VerifyFile{}, cerrors.NewSQLError(http.StatusBadRequest, "文件不存在", nil)
	}

	// 如果文件状态为正常存储就直接返回
	if f.Status > 1 {
		return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, nil
	}

	type ChunkIndex struct {
		ChunkIndex uint64 `gorm:"column:chunk_index"`
		ChunkName  string `gorm:"column:chunk_name"`
	}

	//查询分片
	res := make([]ChunkIndex, 0)
	sql := `select fci.chunk_index,fc.chunk_name 
					from file_chunk as fc inner join file_chunk_index as fci 
					on fc.id = fci.chunk_id and fci.file_id = ? 
					order by fci.chunk_index`
	err := s.DB.Raw(sql, fileId).Scan(&res).Error
	if err != nil {
		logs.ErrorLogger.Error("查询失败", zap.Error(err))
		return VerifyFile{}, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
	}

	// 分片数量不足,要求补全分片
	if uint64(len(res)) != f.Total {

		f.Status = 2
		needChunk := make([]uint64, 0)
		containChunk := make([]uint64, len(res))

		for _, chunk := range res {
			containChunk[chunk.ChunkIndex] = 1
		}

		for i, v := range containChunk {
			if v == 1 {
				continue
			}
			needChunk = append(needChunk, uint64(i))
		}

		return VerifyFile{File: f, NeedChunk: needChunk}, nil
	}

	path := make([]string, len(res))

	for i, chunk := range res {
		path[i] = chunk.ChunkName
	}

	hash, err := toMd5.ChunksToMd5(path)

	if err != nil {
		logs.ErrorLogger.Error("校验出错", zap.Error(err))
		return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, cerrors.NewSQLError(http.StatusInternalServerError, "校验出错", err)
	}

	// 校验分片hash
	if hash != f.FileHash {
		s.cleanFailChunks(ctx, path, fileId)
		logs.ErrorLogger.Error("分片传输出错", zap.String("hash", hash))
		return VerifyFile{File: f}, cerrors.NewSQLError(http.StatusNoContent, "分片传输出错,请重试", nil)
	}

	if err = s.DB.Model(&models.File{}).Where("id = ?", fileId).Update("status", 3).Error; err != nil {
		logs.ErrorLogger.Error("修改文件状态错误", zap.Error(err))
		return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, cerrors.NewSQLError(http.StatusInternalServerError, "修改文件状态错误", err)
	}

	return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, nil
}

func (s *ServiceImpl) cleanFailChunks(ctx context.Context, path []string, fileId id.UUID) {

	// 1. 删除物理分片文件
	for _, chunk := range path {
		if err := os.Remove(chunk); err != nil && !os.IsNotExist(err) {
			logs.ErrorLogger.Warn("删除分片文件失败", zap.String("path", chunk), zap.Error(err))
			// 不立即返回错误，尝试继续清理其他分片
		}
	}

	// 2. 删除数据库中的分片索引记录
	s.DB.Where("file_id = ?", fileId).Delete(&models.FileChunkIndex{})

	// 3. 重置文件状态，标记为需要重新上传
	s.DB.Model(&models.File{}).Where("id = ?", fileId).Update("status", 1)

	// 4. 清理Redis中的相关缓存
	s.Rds.Del(ctx, s.Keys.FileChunkTotalKey(fileId))

}
