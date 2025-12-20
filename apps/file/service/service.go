package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/u2takey/go-utils/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type FileService interface {
	GetRedis() *redis.Client
	InitFileUpload(ctx context.Context, fileList []models.File, targetUserId, requestUserId id.UUID) (files []models.File, uploadId, requestId string, err error)
	UploadChunk(ctx context.Context, fileId id.UUID, chunkIndex uint64, uploadId string, content []byte, chunkContentHash string, requestId string, targetUserId, requestUserId id.UUID) (bool, string, error)
	UploadVerify(ctx context.Context, fileIds []id.UUID, requestId, uploadId string, targetUserId, requestUserId id.UUID) (files []VerifyFile, err error)
	DirectUpload(ctx context.Context, f models.File, content []byte, targetUserId, requestUserId id.UUID) (models.File, error)
	TransferSave(ctx context.Context, aliasId id.UUID, aliasSaveRootId id.UUID, needSelect bool, resolutionStrategy uint64, selectedFileIds []id.UUID, requestId string, targetUserId, requestUserId id.UUID) ([]ReflectFile, string, error)
	ListDirectory(ctx context.Context, aliasId id.UUID, rootType, page, pageSize uint64, requestUserId, targetUserId id.UUID) (files []FileAliasItem, total uint64, err error)
	PreDownLoad(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (aliasName string, requestId string, list []PreDownload, storeType, total uint64, err error)
	Download(ctx context.Context, oneId, requestUserId, targetUserId id.UUID, requestId string, storeType uint64) (content []byte, err error)
	CreateFolder(ctx context.Context, parentAliasId id.UUID, folderName string, isRoot bool, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	RenameFile(ctx context.Context, aliasId id.UUID, newName string, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	MoveFile(ctx context.Context, aliasId id.UUID, newParentId id.UUID, isMoveToRoot bool, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	TrashFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	DeleteFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	RestoreFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error)
	GetFileMeta(ctx context.Context, aliasId, requestUserId, targetUserId id.UUID) (fileAlias FileMeta, err error)
	SearchFile(ctx context.Context, keyword, fileType string, page, pageSize uint64, requestUserId, targetUserId id.UUID) (files []FileAliasItem, total uint64, err error)
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
		logs.ErrorLogger.Error("产生requestId失败",
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return nil, "", "", err
	}

	// 获取uploadId
	uploadId, err = urds.GenerateUploadId(s.Rds, s.Keys, ctx, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("产生uploadId失败",
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return nil, "", "", err
	}

	needs := make([]models.File, 0)

	for _, f := range fileList {
		file, err := s.insertAndRelateFile(ctx, f, targetUserId, requestUserId)
		if err != nil {
			return nil, "", "", err
		}
		needs = append(needs, file)
	}

	return needs, uploadId, requestId, nil
}

func (s *ServiceImpl) UploadChunk(ctx context.Context, fileId id.UUID, chunkIndex uint64, uploadId string, content []byte, chunkHash string, requestId string, targetUserId, requestUserId id.UUID) (verify bool, requestID string, err error) {

	// 校验requestId
	err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("requestId过期",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
	}

	// 校验uploadId
	uploadRs := s.Rds.Get(ctx, s.Keys.UploadIdKey(uploadId)).String()
	if uploadRs == "" {
		logs.ErrorLogger.Error("uploadId过期",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "上传id过期", requestId, nil)
	}
	s.Rds.Expire(ctx, s.Keys.UploadIdKey(uploadId), 24*60*time.Minute)

	// 文件内容hash校验
	hashData := toMd5.ContentToMd5(content)
	if chunkHash != hashData {
		logs.ErrorLogger.Error("分片数据校验失败,请重新传输",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Uint64("chunkIndex", chunkIndex))
		return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "分片数据错误", requestId, nil)
	}

	// 校验分片是否存在
	totalCount, err := s.Rds.Get(ctx, s.Keys.FileChunkTotalKey(fileId)).Uint64()
	storeType, err := s.Rds.Get(ctx, s.Keys.FileChunkTotalKey(fileId)).Uint64()
	if (totalCount <= 0 || storeType <= 0) && err != nil {

		fileExist := models.File{}
		s.DB.Model(&models.File{}).Where("id = ?", fileId).First(&fileExist)
		if fileExist.ID.IsZero() || fileExist.FileHash == "" {
			logs.ErrorLogger.Error("文件不存在,无法传输分片",
				zap.String("uploadId", uploadId),
				zap.String("requestId", requestId),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()))
			return false, requestId, cerrors.NewCommonError(http.StatusBadRequest, "文件不存在", requestId, nil)
		}

		s.Rds.Set(ctx, s.Keys.FileChunkTotalKey(fileId), fileExist.Total, 10*time.Minute)
		s.Rds.Set(ctx, s.Keys.FileChunkStoreTypeKey(fileId), fileExist.StoreType, 10*time.Minute)
	}

	if chunkIndex > totalCount || chunkIndex <= 0 {
		logs.ErrorLogger.Error("分片索引错误",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()))
		return false, "", cerrors.NewCommonError(http.StatusBadRequest, "分片索引错误", requestId, nil)
	}

	s.Rds.Expire(ctx, s.Keys.FileChunkTotalKey(fileId), 10*time.Minute)
	s.Rds.Expire(ctx, s.Keys.FileChunkStoreTypeKey(fileId), 10*time.Minute)

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
				logs.ErrorLogger.Error("数据库记录分片序号错误",
					zap.String("uploadId", uploadId),
					zap.String("requestId", requestId),
					zap.String("targetUserId", targetUserId.MarshalBase64()),
					zap.String("requestUserId", requestUserId.MarshalBase64()),
					zap.Error(err))
				return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入记录失败", requestId, err)
			}
		}

		return true, requestId, nil
	}

	//阿里云存储
	if storeType == 2 {

	}

	return s.uploadToLocal(ctx, fileId, chunkIndex, content, chunkHash, requestId)
}

func (s *ServiceImpl) UploadVerify(ctx context.Context, fileIds []id.UUID, requestId, uploadId string, targetUserId, requestUserId id.UUID) (files []VerifyFile, err error) {

	// 校验requestId
	err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("requestId过期",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
	}

	// 校验uploadId
	uploadRs := s.Rds.Get(ctx, s.Keys.UploadIdKey(uploadId)).String()
	if uploadRs == "" {
		logs.ErrorLogger.Error("uploadId过期",
			zap.String("uploadId", uploadId),
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "上传id过期", requestId, nil)
	}
	s.Rds.Expire(ctx, s.Keys.UploadIdKey(uploadId), 24*60*time.Minute)

	// 验证文件并返回
	files = make([]VerifyFile, len(fileIds))

	for i, fileId := range fileIds {
		f, err := s.verifyFile(ctx, fileId)
		if err != nil {
			return nil, err
		}
		files[i] = f
	}
	return files, nil
}

func (s *ServiceImpl) DirectUpload(ctx context.Context, f models.File, content []byte, targetUserId, requestUserId id.UUID) (models.File, error) {

	f.Status = 2

	hash := toMd5.ContentToMd5(content)

	f.FileName = filepath.Base(f.FileName)

	if hash != f.FileHash {
		logs.ErrorLogger.Error("传输内容错误",
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()))
		return models.File{}, cerrors.NewCommonError(http.StatusBadRequest, "传输内容错误,请重传", "", nil)
	}

	relateFile, err := s.insertAndRelateFile(ctx, f, targetUserId, requestUserId)

	if err != nil {
		return models.File{}, err
	}

	// 文件不存在就进行传输
	if relateFile.Status != MERGESTORE && relateFile.Status != CHUNKSTORE {
		if f.StoreType == 2 {
			//阿里云存储

		} else {
			//本地存储
			path, err := s.writeContentToFile(content, hash, "")
			if err != nil {
				return models.File{}, err
			}
			f.DirectPath = path
		}
	}

	err = s.DB.Model(&models.File{}).Where("id = ?", relateFile.ID).Update("status", 4).Update("direct_path", f.DirectPath).Error

	if err != nil {
		logs.ErrorLogger.Error("更新文件信息错误,请重试",
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新文件信息错误,请重试", err)
	}

	return relateFile, nil
}

func (s *ServiceImpl) TransferSave(ctx context.Context, aliasId id.UUID, aliasSaveRootId id.UUID, needSelect bool, resolutionStrategy uint64, selectedFileIds []id.UUID, requestId string, targetUserId, requestUserId id.UUID) ([]ReflectFile, string, error) {

	/// TODO 之后请将长事务改为最终一致性方案,考虑的决策为消息队列异步提交+错误补偿

	var err error

	//如果需要进行手动选择校验requestId,否则产生requestId即可
	if needSelect {
		err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
		if err != nil {
			logs.ErrorLogger.Error("requestId过期",
				zap.String("requestId", requestId),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Bool("needSelect", needSelect),
				zap.Uint64("resolutionStrategy", resolutionStrategy),
				zap.Error(err))
			return nil, "", cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
		}
	} else {
		requestId, err = urds.GenerateRequestId(s.Rds, s.Keys, ctx, 20*60*time.Minute)
		if err != nil {
			logs.ErrorLogger.Error("产生requestId失败",
				zap.String("requestId", requestId),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Bool("needSelect", needSelect),
				zap.Uint64("resolutionStrategy", resolutionStrategy),
				zap.Error(err))
			return nil, "", cerrors.NewCommonError(http.StatusInternalServerError, "产生requestId失败", requestId, err)
		}
	}

	//以aliasId为根节点递归向下查询

	aliasItems, err := s.takeFileList(ctx, aliasId, true, targetUserId, requestUserId)

	if err != nil {
		logs.ErrorLogger.Error("查询节点失败",
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("needSelect", needSelect),
			zap.Uint64("resolutionStrategy", resolutionStrategy),
			zap.Error(err))
		return nil, requestId, cerrors.NewSQLError(http.StatusBadRequest, "查询节点失败", err)
	}

	//如果aliasId不存在,直接返回ok即可
	if len(aliasItems) == 0 {
		return nil, requestId, nil
	}

	// 初始化响应参数
	resp := make([]ReflectFile, 0)
	insertData := make([]models.FileAlias, 0)

	// 构建被选择的文件哈希表
	selectIdMap := make(map[id.UUID]struct{})
	if selectedFileIds != nil {
		for _, idItem := range selectedFileIds {
			selectIdMap[idItem] = struct{}{}
		}
	}

	// 构建需要被保存的文件树
	tree := s.buildNeedSavedTree(aliasId, aliasSaveRootId, aliasItems, requestUserId)

	tx := s.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	queue := make([]*FileAliasNode, 0, len(aliasItems))
	for _, v := range tree {
		queue = append(queue, v)
	}

	for len(queue) > 0 {
		// 出队数据
		head := queue[0]
		queue = queue[1:]

		//基于队列进行写入
		children := head.Children
		for _, child := range children {
			queue = append(queue, child)
		}

		//初始化写入数据
		data := head.FileAlias
		data.ParentID = head.Father.FileAlias.ID
		data.ID = id.NewUUID()
		queryRes := models.FileAlias{}

		// 不能直接写,需要查询路径是否存在
		if !head.NoRead {
			err = tx.Model(&models.FileAlias{}).Where("parent_id = ? and file_name = ? and user_id = ?", data.ParentID, data.FileName, data.UserID).First(&queryRes).Error
			if err != nil {
				logs.ErrorLogger.Error("查询路径失败", zap.Error(err))
				return nil, requestId, cerrors.NewSQLError(http.StatusBadRequest, "查询路径失败", err)
			}
		}

		// 查询到路径存在而且为文件夹,直接重置id后跳过
		if !queryRes.ID.IsZero() && data.IsDirectory {
			data.ID = queryRes.ID
			continue
		}

		// 查询到路径存在且为文件,根据传入参数进行判断
		if !queryRes.ID.IsZero() && !data.IsDirectory {
			data.ID = queryRes.ID
			switch resolutionStrategy {
			case 1: // 默认状态,有问题失败
				return nil, requestId, cerrors.NewSQLError(http.StatusBadRequest, "文件存在冲突,请解决", nil)
			case 2: // 覆盖,有冲突就覆盖
				err = tx.Model(&models.FileAlias{}).Update("file_id = ?", data.FileID).Where("id = ?", data.ID).Error
				if err != nil {
					logs.ErrorLogger.Error("写入节点失败",
						zap.String("requestId", requestId),
						zap.String("targetUserId", targetUserId.MarshalBase64()),
						zap.String("requestUserId", requestUserId.MarshalBase64()),
						zap.Bool("needSelect", needSelect),
						zap.Uint64("resolutionStrategy", resolutionStrategy),
						zap.Error(err))
					return nil, requestId, cerrors.NewSQLError(http.StatusBadRequest, "写入节点失败", err)
				}
				continue
			case 3: // 跳过,有冲突就直接不管跳过
				continue
			case 4: // 重命名,有问题就重命名为唯一文件
				data.ID = id.NewUUID()
				data.FileName = uuid.NewUUID()
			case 5: // 取消转存,直接返回,不做任何处理
				return nil, requestId, nil
			case 6: // 自行选择保留哪一个文件

				// 需要进行自主选择,构建并返回
				if needSelect {
					resp = append(resp, ReflectFile{
						OldFileId: queryRes.FileID,
						NewFIleId: data.FileID,
						FileName:  data.FileName,
					})
					continue
				}

				// 得到构建结果,开始处理
				if _, ok := selectIdMap[queryRes.FileID]; ok { // 如果旧节点被选择,就直接跳过而不构建
					continue
				} else if _, ok = selectIdMap[data.FileID]; ok { // 新节点被选择,就直接构建新节点
					data.ID = id.NewUUID()
				} else {
					logs.ErrorLogger.Error("部分选择不存在,请重新选择",
						zap.String("requestId", requestId),
						zap.String("targetUserId", targetUserId.MarshalBase64()),
						zap.String("requestUserId", requestUserId.MarshalBase64()),
						zap.Bool("needSelect", needSelect),
						zap.Uint64("resolutionStrategy", resolutionStrategy))
					return nil, requestId, cerrors.NewParamError(http.StatusBadRequest, "部分选择不存在,请重新选择")
				}
			default:
				logs.ErrorLogger.Error("文件存在冲突,请解决",
					zap.String("requestId", requestId),
					zap.String("targetUserId", targetUserId.MarshalBase64()),
					zap.String("requestUserId", requestUserId.MarshalBase64()),
					zap.Bool("needSelect", needSelect),
					zap.Uint64("resolutionStrategy", resolutionStrategy))
				return nil, requestId, cerrors.NewSQLError(http.StatusBadRequest, "文件存在冲突,请解决", nil)
			}
		}

		// 查询到路径不存在,直接对其子节点写入“无需读”标记
		for _, v := range head.Children {
			v.NoRead = true
		}

		// 写入节点
		insertData = append(insertData, data)
	}

	// 需要自行选择,返回结果
	if needSelect {
		return resp, requestId, nil
	}

	// 写入数据
	err = tx.Model(&models.FileAlias{}).Create(&insertData).Error
	if err != nil {
		logs.ErrorLogger.Error("转存失败,请重试",
			zap.String("requestId", requestId),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("needSelect", needSelect),
			zap.Uint64("resolutionStrategy", resolutionStrategy),
			zap.Error(err))
		return nil, requestId, err
	}

	tx.Commit()
	return nil, requestId, nil
}

func (s *ServiceImpl) ListDirectory(ctx context.Context, aliasId id.UUID, rootType, page, pageSize uint64, requestUserId, targetUserId id.UUID) (files []FileAliasItem, total uint64, err error) {

	// 如果查询的是根目录开始,就跳过前置查询
	switch rootType {
	case 1: //根目录
		aliasId = id.EmptyUUID
	case 2: //非根目录
		_, err = s.takeSingleFileAlias(ctx, aliasId, targetUserId, requestUserId)
		if err != nil {
			return nil, 0, err
		}
	case 3: // 回收站目录
		aliasId = id.RecycleUUID
	default:
		return nil, 0, cerrors.NewCommonError(http.StatusBadRequest, "查询类型错误", "", nil)
	}

	var count int64

	Rs, err := s.Rds.Get(ctx, s.Keys.FileAliasKey(aliasId)).Uint64()

	if err != nil {
		err = s.DB.Model(&models.FileAlias{}).Where("parent_id = ?", aliasId).Count(&count).Error
		if err != nil {
			logs.ErrorLogger.Error("请求错误",
				zap.String("aliasId", aliasId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Uint64("page", page),
				zap.Uint64("pageSize", pageSize),
				zap.Uint64("rootType(1:根目录 2:非根目录 3:回收站目录)", rootType),
				zap.Error(err))
			return nil, 0, cerrors.NewSQLError(http.StatusInternalServerError, "请求错误", err)
		}
		s.Rds.Set(ctx, s.Keys.FileAliasKey(aliasId), count, 20*time.Minute)
	}

	count = int64(Rs)

	// 查询当前目录id下的子目录
	listQuery := urds.ListCacheComponent[id.UUID, models.FileAlias]{
		Rds:             s.Rds,
		Ctx:             ctx,
		ListKey:         s.Keys.FileAliasListKeyWithFunc(aliasId, "ListDirectory", page, pageSize),
		DetailKeyPrefix: s.Keys.FileAliasKeyPrefix(),
		Marshal:         json.Marshal,
		Unmarshal:       json.Unmarshal,
		FullQueryExec: func() ([]models.FileAlias, error) {
			res := make([]models.FileAlias, 0)

			offset := (page - 1) * pageSize

			err = s.DB.Model(&models.FileAlias{}).Where("parent_id = ? and user_id = ?", aliasId, requestUserId).Offset(int(offset)).Limit(int(pageSize)).Find(&res).Error
			if err != nil {
				return nil, err
			}
			return res, nil
		},
		PartQueryExec: func(fails []id.UUID) ([]models.FileAlias, error) {
			res := make([]models.FileAlias, 0)
			err = s.DB.Model(&models.FileAlias{}).Where("id in ?", fails).Find(&res).Error
			if err != nil {
				return nil, err
			}
			return res, nil
		},
		Expires:     30 * time.Minute,
		Random:      2 * time.Minute,
		MaxLostRate: 30,
		Sort: func(aliases []models.FileAlias) []models.FileAlias {
			return aliases
		},
	}
	res, err := listQuery.QueryListWithCache()
	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Uint64("page", page),
			zap.Uint64("pageSize", pageSize),
			zap.Uint64("rootType(1:根目录 2:非根目录 3:回收站目录)", rootType),
			zap.Error(err))
		return nil, 0, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
	}

	// 将每个文件目录进行填充
	ans, err := s.fillFileAliasWithFile(ctx, res, s.Keys.FileListKeyWithFunc(aliasId, "ListDirectory", page, pageSize))

	if err != nil {
		return nil, 0, err
	}

	return ans, uint64(count), nil
}

func (s *ServiceImpl) PreDownLoad(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (aliasName string, requestId string, list []PreDownload, storeType, total uint64, err error) {
	// 生产requestId
	requestId, err = urds.GenerateRequestId(s.Rds, s.Keys, ctx, 20*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("产生requestId失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return "", "", nil, 0, 0, cerrors.NewCommonError(http.StatusInternalServerError, "产生requestId失败", requestId, err)
	}

	// 查询文件信息
	sqlStmt := `select f.* from file as f inner join file_alias as fa on fa.file_id = f.id and fa.is_directory = 0 where fa.id = ?`
	res := models.File{}

	// 如果文件不存在或者没有上传成功就显示查询失败
	err = s.DB.Raw(sqlStmt, aliasId).Scan(&res).Error
	if err != nil {
		logs.ErrorLogger.Error("查询文件失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return "", "", nil, 0, 0, cerrors.NewSQLError(http.StatusInternalServerError, "查询文件失败", err)
	}

	if res.ID.IsZero() || (res.Status != MERGESTORE && res.Status != CHUNKSTORE) {
		logs.ErrorLogger.Error("文件不存在",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()))
		return "", "", nil, 0, 0, cerrors.NewCommonError(http.StatusBadRequest, "文件不存在", "", errors.New("文件不存在"))
	}

	// 查询到文件信息后根据信息去查询文件信息
	aliasName = uuid.NewUUID() + "." + res.FileType

	list = make([]PreDownload, 0)

	// 本地合并存储
	if res.Status == MERGESTORE && res.StoreType == 1 {
		list = append(list, PreDownload{
			FileId: res.ID.MarshalBase64(),
		})
		return aliasName, requestId, list, res.Status, res.Total, nil
	}

	// 本地分片存储
	if res.Status == CHUNKSTORE && res.StoreType == 1 {
		sqlStmt = `select fc.*,fci.chunk_index from
             file as f
                 inner join
             file_chunk_index as fci
                 inner join
             file_chunk as fc
                 on f.id = fci.file_id and fc.id in (fci.chunk_id)
                 where f.id = ?
                 order by fci.chunk_index`

		type ChunkMsg struct {
			models.FileChunk
			ChunkIndex uint64 `json:"chunk_index"`
		}

		//读取分片信息
		chunks := make([]ChunkMsg, 0)
		err = s.DB.Raw(sqlStmt, res.ID).Scan(&chunks).Error
		if err != nil {
			logs.ErrorLogger.Error("读取分片信息失败",
				zap.String("aliasId", aliasId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Error(err))
			return "", "", nil, 0, 0, cerrors.NewSQLError(http.StatusInternalServerError, "读取分片信息失败", err)
		}

		// 组装结果
		for _, chunk := range chunks {

			pd := PreDownload{
				ChunkId:    chunk.ID.MarshalBase64(),
				ChunkIndex: chunk.ChunkIndex,
			}

			list = append(list, pd)
		}
		return aliasName, requestId, list, res.Status, res.Total, nil
	}

	logs.ErrorLogger.Error("错误的请求,没有符合条件的组合,请注意",
		zap.String("aliasId", aliasId.MarshalBase64()),
		zap.String("targetUserId", targetUserId.MarshalBase64()),
		zap.String("requestUserId", requestUserId.MarshalBase64()))
	return "", "", nil, 0, 0, cerrors.NewSQLError(http.StatusBadRequest, "请求错误", err)
}

func (s *ServiceImpl) Download(ctx context.Context, id, requestUserId, targetUserId id.UUID, requestId string, storeType uint64) (content []byte, err error) {

	// 校验requestId
	err = urds.VerityRequestID(s.Rds, s.Keys, ctx, requestId, 24*60*time.Minute)
	if err != nil {
		logs.ErrorLogger.Error("requestId过期",
			zap.String("requestId", requestId),
			zap.String("id", id.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Uint64("storeType(3:分片存储 4:合并存储)", storeType),
			zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "请求过期", requestId, err)
	}

	findPath := ""
	hash := ""

	// 合并存储
	if storeType == MERGESTORE {
		res := models.File{}
		err = s.DB.Model(&models.File{}).Where("id = ?", id).First(&res).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			logs.ErrorLogger.Error("查询失败",
				zap.String("requestId", requestId),
				zap.String("id", id.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Uint64("storeType(3:分片存储 4:合并存储)", storeType),
				zap.Error(err))
			return nil, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
		}
		findPath = res.DirectPath
		hash = res.FileHash
	}

	// 分片存储
	if storeType == CHUNKSTORE {
		res := models.FileChunk{}
		err = s.DB.Model(&models.FileChunk{}).Where("id = ?", id).First(&res).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			logs.ErrorLogger.Error("查询失败",
				zap.String("requestId", requestId),
				zap.String("id", id.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Uint64("storeType(3:分片存储 4:合并存储)", storeType),
				zap.Error(err))
			return nil, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
		}
		findPath = res.ChunkName
		hash = res.ChunkHash
	}

	if findPath == "" || hash == "" {
		logs.ErrorLogger.Error("数据已损坏",
			zap.String("requestId", requestId),
			zap.String("id", id.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Uint64("storeType(3:分片存储 4:合并存储)", storeType),
			zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusBadRequest, "数据已损坏", requestId, err)
	}

	bytes, err := s.readFile(findPath, hash)

	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (s *ServiceImpl) CreateFolder(ctx context.Context, parentAliasId id.UUID, folderName string, isRoot bool, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {

	if !isRoot {
		// 查询父文件夹是否存在
		parentRs, err := s.takeSingleFileAliasWithCleanCache(ctx, parentAliasId, targetUserId, requestUserId)
		if err != nil {
			return models.FileAlias{}, err
		}
		// 查询父文件夹是否为文件夹
		if !parentRs.IsDirectory {
			logs.ErrorLogger.Error("父文件夹类型错误",
				zap.String("parentAliasId", parentAliasId.MarshalBase64()),
				zap.String("folderName", folderName),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Bool("isRoot", isRoot),
				zap.Error(err))
			return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "父文件夹类型错误", err)
		}
	} else {
		parentAliasId = id.EmptyUUID
	}

	// 检测是否有重复文件夹
	var Count int64
	err = s.DB.Model(&models.FileAlias{}).Where("parent_id = ? and user_id = ? and file_name = ? and is_directory = 1", parentAliasId, targetUserId, folderName).Count(&Count).Error

	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("parentAliasId", parentAliasId.MarshalBase64()),
			zap.String("folderName", folderName),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("isRoot", isRoot),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
	}

	// 存在重复文件夹,报错返回
	if Count > 0 {
		logs.ErrorLogger.Error("文件夹已存在,不可重复创建",
			zap.String("parentAliasId", parentAliasId.MarshalBase64()),
			zap.String("folderName", folderName),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("isRoot", isRoot),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "文件夹已存在,不可重复创建", err)
	}

	// 创建目标文件夹
	now := time.Now()
	data := models.FileAlias{
		ID:          id.NewUUID(),
		UserID:      targetUserId,
		ParentID:    parentAliasId,
		FileName:    folderName,
		CreatedAt:   &now,
		IsDirectory: true,
	}

	err = s.DB.Model(&models.FileAlias{}).Create(&data).Error
	if err != nil {
		logs.ErrorLogger.Error("创建失败",
			zap.String("parentAliasId", parentAliasId.MarshalBase64()),
			zap.String("folderName", folderName),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("isRoot", isRoot),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "创建失败", err)
	}

	return data, nil
}

func (s *ServiceImpl) RenameFile(ctx context.Context, aliasId id.UUID, newName string, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {

	// 查询文件夹
	rs, err := s.takeSingleFileAliasWithCleanCache(ctx, aliasId, targetUserId, requestUserId)
	if err != nil {
		return models.FileAlias{}, err
	}

	err = s.DB.Model(&models.FileAlias{}).Where("id = ?", rs.ID).Update("file_name", newName).Error
	if err != nil {
		logs.ErrorLogger.Error("更改失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("newName", newName),
			zap.String("targetUserId", targetUserId.String()),
			zap.String("requestUserId", requestUserId.String()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "更改失败", err)
	}

	rs.FileName = newName
	return rs, nil
}

func (s *ServiceImpl) MoveFile(ctx context.Context, aliasId id.UUID, newParentId id.UUID, isMoveToRoot bool, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {

	rs, err := s.takeSingleFileAliasWithCleanCache(ctx, aliasId, targetUserId, requestUserId)
	if err != nil {
		return models.FileAlias{}, err
	}

	// 构建新父Id
	if !isMoveToRoot {
		parentRs, err := s.takeSingleFileAliasWithCleanCache(ctx, newParentId, targetUserId, requestUserId)
		if err != nil {
			return models.FileAlias{}, err
		}
		if !parentRs.IsDirectory {
			logs.ErrorLogger.Error("移动到的目录不是文件夹目录,请重试",
				zap.String("aliasId", aliasId.MarshalBase64()),
				zap.String("newParentId", newParentId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Bool("isMoveToRoot", isMoveToRoot),
				zap.Error(err))
			return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "移动到的目录不是文件夹目录,请重试", nil)
		}
	} else {
		newParentId = id.EmptyUUID
	}

	// 如果新旧相同,不变
	if rs.ParentID == newParentId {
		return rs, nil
	}

	// 更新父id
	rs.ParentID = newParentId
	err = s.DB.Model(&models.FileAlias{}).Where("id = ?", rs.ID).Update("parent_id = ?", newParentId).Error
	if err != nil {
		logs.ErrorLogger.Error("更新失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("newParentId", newParentId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Bool("isMoveToRoot", isMoveToRoot),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "更新失败", err)
	}

	return rs, nil
}

func (s *ServiceImpl) TrashFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {

	// 查询文件信息
	rs, err := s.takeSingleFileAliasWithCleanCache(ctx, aliasId, targetUserId, requestUserId)
	if err != nil {
		return models.FileAlias{}, err
	}

	// 更新文件数据
	now := time.Now()
	rs.UpdatedAt = &now
	rs.RecoveryID = rs.ParentID
	rs.ParentID = id.RecycleUUID

	updates := map[string]interface{}{
		"updated_at":  &now,
		"recovery_id": rs.RecoveryID,
		"parent_id":   rs.ParentID,
		"file_name":   now.Format("20060102150405_") + rs.FileName,
	}

	err = s.DB.Model(&models.FileAlias{}).Where("id = ?", rs.ID).Updates(updates).Error
	if err != nil {
		logs.ErrorLogger.Error("更新失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新失败", err)
	}

	return rs, nil
}

func (s *ServiceImpl) DeleteFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {

	// 查询文件信息
	rs, err := s.takeSingleFileAliasWithCleanCache(ctx, aliasId, targetUserId, requestUserId)

	if err != nil {
		return models.FileAlias{}, err
	}

	// 文件不在回收站中,不允许直接删除
	if rs.ParentID != id.RecycleUUID {
		logs.ErrorLogger.Error("文件不在回收站中,无法直接删除",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()))
		return models.FileAlias{}, cerrors.NewCommonError(http.StatusBadRequest, "文件不在回收站中,无法直接删除", "", nil)
	}

	// 硬删除数据
	err = s.DB.Model(&models.FileAlias{}).Unscoped().Delete(&rs).Error
	if err != nil {
		logs.ErrorLogger.Error("删除失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "删除失败", err)
	}

	return rs, nil

}

func (s *ServiceImpl) RestoreFile(ctx context.Context, aliasId id.UUID, requestUserId, targetUserId id.UUID) (fileAlias models.FileAlias, err error) {
	// 查询文件信息
	rs, err := s.takeSingleFileAliasWithCleanCache(ctx, aliasId, targetUserId, requestUserId)

	if err != nil {
		return models.FileAlias{}, err
	}

	// 文件不在回收站中,不需要回收
	if rs.ParentID != id.RecycleUUID {
		return rs, nil
	}

	// 更新数据
	now := time.Now()
	rs.UpdatedAt = &now
	rs.ParentID = rs.RecoveryID
	rs.RecoveryID = id.EmptyUUID

	updates := map[string]interface{}{
		"updated_at":  &now,
		"parent_id":   rs.ParentID,
		"recovery_id": nil,
	}

	err = s.DB.Model(&models.FileAlias{}).Where("id = ?", rs.ID).Updates(updates).Error

	if err != nil {
		logs.ErrorLogger.Error("更新失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新失败", err)
	}

	return rs, nil
}

func (s *ServiceImpl) GetFileMeta(ctx context.Context, aliasId, requestUserId, targetUserId id.UUID) (fileAlias FileMeta, err error) {
	// 查询文件信息
	rs, err := s.takeSingleFileAlias(ctx, aliasId, targetUserId, requestUserId)

	if err != nil {
		return FileMeta{}, err
	}

	result := FileMeta{}

	result.IsDirectory = rs.IsDirectory
	result.FileName = rs.FileName
	result.AliasId = rs.ID.MarshalBase64()
	result.CreatedAt = rs.CreatedAt.Format("2006-01-02 15:04:05")
	result.UpdatedAt = rs.UpdatedAt.Format("2006-01-02 15:04:05")

	// 非文件直接返回
	if result.IsDirectory {
		return result, nil
	}

	// 查询文件本体填充信息
	file, err := s.takeSingleFile(ctx, aliasId, targetUserId, requestUserId)

	if err != nil {
		return FileMeta{}, err
	}

	result.FileId = file.ID.MarshalBase64()
	result.FileContentHash = file.FileHash
	result.FileSize = file.FileSize
	result.FileCover = file.FileCover
	result.Status = file.Status
	result.FileType = file.FileType

	return result, nil
}

func (s *ServiceImpl) SearchFile(ctx context.Context, keyword, fileType string, page, pageSize uint64, requestUserId, targetUserId id.UUID) (files []FileAliasItem, total uint64, err error) {

	//查询文件(夹)目录
	listQuery := urds.ListCacheComponent[id.UUID, models.FileAlias]{
		Rds:             s.Rds,
		Ctx:             ctx,
		ListKey:         s.Keys.FileAliasListKeyWithFunc(targetUserId, "SearchFile", page, pageSize, keyword, fileType),
		DetailKeyPrefix: s.Keys.FileAliasKeyPrefix(),
		Marshal:         json.Marshal,
		Unmarshal:       json.Unmarshal,
		FullQueryExec: func() ([]models.FileAlias, error) {
			var res []models.FileAlias

			// 安全地构建搜索条件
			var searchCondition string
			if keyword != "" && fileType != "" {
				searchCondition = "+" + keyword + " +" + fileType
			} else if keyword != "" {
				searchCondition = "+" + keyword
			} else if fileType != "" {
				searchCondition = "+" + fileType
			} else {
				searchCondition = ""
			}

			offset := (page - 1) * pageSize

			sqlStmt := `select * from file_alias where match(file_name) against(? in boolean mode) and user_id = ?`

			err := s.DB.Raw(sqlStmt, searchCondition, targetUserId).Offset(int(offset)).Limit(int(pageSize)).Scan(&res).Error

			if err != nil {
				return nil, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
			}

			return res, nil
		},
		PartQueryExec: func(fails []id.UUID) ([]models.FileAlias, error) {
			res := make([]models.FileAlias, 0)
			err = s.DB.Model(&models.FileAlias{}).Where("id in ?", fails).Find(&res).Error
			if err != nil {
				return nil, err
			}
			return res, nil
		},
		Expires:     30 * time.Minute,
		Random:      2 * time.Minute,
		MaxLostRate: 30,
		Sort: func(aliases []models.FileAlias) []models.FileAlias {
			return aliases
		},
	}

	res, err := listQuery.QueryListWithCache()
	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("keyword", keyword),
			zap.String("fileType", fileType),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Uint64("page", page),
			zap.Uint64("pageSize", pageSize),
			zap.Error(err))
		return nil, 0, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
	}

	// 将每个文件目录进行填充
	ans, err := s.fillFileAliasWithFile(ctx, res, s.Keys.FileListKeyWithFunc(targetUserId, "SearchFile", page, pageSize, keyword, fileType))

	if err != nil {
		return nil, 0, err
	}

	return ans, uint64(len(ans)), nil
}

func (s *ServiceImpl) fillFileAliasWithFile(ctx context.Context, res []models.FileAlias, fileListKey string) (files []FileAliasItem, err error) {
	ans := make([]FileAliasItem, len(res))

	fileIdList := make([]id.UUID, 0)
	for _, v := range res {
		if !v.FileID.IsZero() {
			fileIdList = append(fileIdList, v.FileID)
		}
	}

	FileMap := map[id.UUID]models.File{}

	//如果存在文件就查询一次文件信息
	if len(fileIdList) != 0 {
		fileListQuery := urds.ListCacheComponent[id.UUID, models.File]{
			Rds:             s.Rds,
			Ctx:             ctx,
			ListKey:         fileListKey,
			DetailKeyPrefix: s.Keys.FileKeyPrefix(),
			Marshal:         json.Marshal,
			Unmarshal:       json.Unmarshal,
			FullQueryExec: func() ([]models.File, error) {
				data := make([]models.File, 0)
				err = s.DB.Model(&models.File{}).Where("id in ?", fileIdList).Find(&data).Error
				if err != nil {
					return nil, err
				}
				return data, nil
			},
			PartQueryExec: func(fails []id.UUID) ([]models.File, error) {
				data := make([]models.File, 0)
				err = s.DB.Model(&models.File{}).Where("id in ?", fails).Find(&data).Error
				if err != nil {
					return nil, err
				}
				return data, nil
			},
			Expires:     30 * time.Minute,
			Random:      2 * time.Minute,
			MaxLostRate: 30,
			Sort: func(aliases []models.File) []models.File {
				return aliases
			},
		}

		fileList, err := fileListQuery.QueryListWithCache()
		if err != nil {
			logs.ErrorLogger.Error("查询失败",
				zap.String("fileListKey", fileListKey),
				zap.Error(err))
			return nil, err
		}
		for _, v := range fileList {
			FileMap[v.ID] = v
		}
	}

	for i, v := range res {
		ans[i] = FileAliasItem{
			FileName:    v.FileName,
			AliasID:     v.ID,
			CreatedAt:   "",
			IsDirectory: v.IsDirectory,
		}
		if item, ok := FileMap[v.FileID]; ok {
			ans[i].FileType = item.FileType
			ans[i].FileCover = item.FileCover
			ans[i].FileSize = item.FileSize
			ans[i].FileID = item.ID
		}
	}

	return ans, nil
}

func (s *ServiceImpl) insertAndRelateFile(ctx context.Context, file models.File, targetUserId, requestUserId id.UUID) (models.File, error) {

	var res models.File

	err := s.DB.WithContext(ctx).Model(&models.File{}).Where("file_hash = ?", file.FileHash).First(&res).Error //查询文件是否存在

	alias := file.FileName

	// 不存在就直接创建
	if res.FileHash == "" || res.ID.IsZero() {
		file.ID = id.NewUUID()
		file.Status = 1
		err := s.DB.Create(&file).Error
		if err != nil {
			logs.ErrorLogger.Error("创建文件错误",
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.Error(err))
			return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "创建文件错误", err)
		}
		res = file
	}

	// 校验文件是否被关联
	var count int64 = 0
	s.DB.Model(&models.FileAlias{}).Where("file_id = ? and user_id = ?", res.ID, targetUserId).Count(&count)

	if count > 0 {
		return res, nil
	}

	now := time.Now()

	tx := s.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	// 创建文件路径与用户的关联
	splitPaths := SplitPathToLevels(alias)
	parentId := id.EmptyUUID
	needFind := true

	for i, path := range splitPaths {

		fa := models.FileAlias{}

		if needFind {
			tx.Model(&models.FileAlias{}).
				Where(" parent_id = ? and user_id = ? and file_name = ?", parentId, targetUserId, path).
				First(&fa)
		}

		if !fa.ID.IsZero() {
			parentId = fa.ID
			needFind = false
			continue
		}

		fa = models.FileAlias{
			ID:          id.NewUUID(),
			UserID:      targetUserId,
			ParentID:    parentId,
			FileName:    path,
			CreatedAt:   &now,
			IsDirectory: i < len(splitPaths)-1,
		}

		if i == len(splitPaths)-1 {
			fa.FileID = res.ID
		}

		err = tx.Model(&models.FileAlias{}).Create(&fa).Error
		if err != nil {
			logs.ErrorLogger.Error("更新错误",
				zap.String("fileHash", file.FileHash),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.Error(err))
			return models.File{}, cerrors.NewSQLError(http.StatusInternalServerError, "更新错误", err)
		}

		parentId = fa.ID
	}

	tx.Commit()

	s.Rds.Set(ctx, s.Keys.FileChunkTotalKey(res.ID), res.Total, 10*time.Minute)

	return res, nil
}

func (s *ServiceImpl) takeSingleFileAlias(ctx context.Context, aliasId id.UUID, targetUserId, requestUserId id.UUID) (file models.FileAlias, err error) {
	simpleQuery := urds.SimpleCacheComponent[id.UUID, models.FileAlias]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       s.Keys.FileAliasKey(aliasId),
		Marshal:   json.Marshal,
		Unmarshal: json.Unmarshal,
		QueryExec: func() (models.FileAlias, error) {
			res := models.FileAlias{}
			err = s.DB.Model(&models.FileAlias{}).Where("id = ? and user_id = ?", aliasId, targetUserId).Find(&res).Error
			if err != nil {
				return models.FileAlias{}, err
			}

			if res.ID.IsZero() {
				return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "请求目标不存在", err)
			}

			return res, nil
		},
		Expires: 30 * time.Minute,
		Random:  2 * time.Minute,
	}

	aliasFile, err := simpleQuery.QueryWithCache()
	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, err
	}

	if !aliasFile.IsDirectory {
		logs.ErrorLogger.Error("文件无法查询子目录",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, err
	}

	return aliasFile, nil
}

func (s *ServiceImpl) takeSingleFile(ctx context.Context, fileId id.UUID, targetUserId, requestUserId id.UUID) (file models.File, err error) {
	simpleQuery := urds.SimpleCacheComponent[id.UUID, models.File]{
		Rds:       s.Rds,
		Ctx:       ctx,
		Key:       s.Keys.FileKey(fileId),
		Marshal:   json.Marshal,
		Unmarshal: json.Unmarshal,
		QueryExec: func() (models.File, error) {
			res := models.File{}
			err = s.DB.Model(&models.File{}).Where("id = ?", fileId, targetUserId).Find(&res).Error
			if err != nil {
				return models.File{}, err
			}

			if res.ID.IsZero() {
				return models.File{}, cerrors.NewSQLError(http.StatusBadRequest, "请求文件不存在", err)
			}

			return res, nil
		},
		Expires: 30 * time.Minute,
		Random:  2 * time.Minute,
	}

	File, err := simpleQuery.QueryWithCache()
	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("fileId", fileId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.Error(err))
		return models.File{}, err
	}

	return File, nil
}

func (s *ServiceImpl) takeSingleFileAliasWithCleanCache(ctx context.Context, aliasId id.UUID, targetUserId, requestUserId id.UUID) (file models.FileAlias, err error) {
	rs := models.FileAlias{}
	err = s.DB.Model(&models.FileAlias{}).Where("id = ? and user_id = ?", aliasId, targetUserId).First(&rs).Error
	if err != nil {
		logs.ErrorLogger.Error("查询失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusInternalServerError, "查询失败", err)
	}

	if rs.ID.IsZero() {
		logs.ErrorLogger.Error("文件不存在",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return models.FileAlias{}, cerrors.NewSQLError(http.StatusBadRequest, "文件不存在", err)
	}

	s.Rds.Del(ctx, s.Keys.FileAliasKey(aliasId))

	return rs, nil
}

func (s *ServiceImpl) takeFileList(ctx context.Context, aliasId id.UUID, isRecursive bool, targetUserId, requestUserId id.UUID) (aliasItems []models.FileAlias, err error) {
	if isRecursive {
		return s.recursiveTakeFileList(ctx, aliasId, targetUserId, requestUserId)
	}
	return s.iterateTakeFileList(ctx, aliasId, targetUserId, requestUserId)
}

func (s *ServiceImpl) recursiveTakeFileList(ctx context.Context, aliasId id.UUID, targetUserId, requestUserId id.UUID) (aliasItems []models.FileAlias, err error) {

	//以aliasId为根节点递归向下查询
	sqlStmt := `with recursive file_tree as(
    select *, ? as level from file_alias where id = ? and user_id = ?
            		union all
    select fa.*,ft.level+1 from file_alias as fa inner join file_tree ft on fa.parent_id=ft.id
	)
	select * from file_tree order by level;`
	aliasItems = make([]models.FileAlias, 0)
	err = s.DB.Raw(sqlStmt, 1, aliasId, targetUserId).Scan(&aliasItems).Error
	if err != nil {
		logs.ErrorLogger.Error("查询被转存节点失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return nil, cerrors.NewSQLError(http.StatusBadRequest, "查询被转存节点失败", err)
	}
	return aliasItems, nil
}

func (s *ServiceImpl) iterateTakeFileList(ctx context.Context, aliasId id.UUID, targetUserId, requestUserId id.UUID) (aliasItems []models.FileAlias, err error) {

	aliasItems = make([]models.FileAlias, 0)

	queue := make([]models.FileAlias, 0)
	root := models.FileAlias{}

	err = s.DB.Model(&models.FileAlias{}).Where("id = ? and user_id = ?", aliasId, targetUserId).Find(&root).Error
	if err != nil {
		logs.ErrorLogger.Error("查询节点失败",
			zap.String("aliasId", aliasId.MarshalBase64()),
			zap.String("targetUserId", targetUserId.MarshalBase64()),
			zap.String("requestUserId", requestUserId.MarshalBase64()),
			zap.Error(err))
		return nil, cerrors.NewSQLError(http.StatusBadRequest, "查询节点失败", err)
	}

	// 初始化队头
	if !root.ID.IsZero() {
		queue = append(queue, root)
	}

	//层次遍历
	for len(queue) > 0 {

		//取出队头数据
		head := queue[0]
		queue = queue[1:]

		// 将节点写入结果
		aliasItems = append(aliasItems, head)

		// 当前节点为文件,直接跳过
		if !head.IsDirectory {
			continue
		}

		//逐层取出数据
		children := make([]models.FileAlias, 0)
		err = s.DB.Model(&models.FileAlias{}).Where("parent_id = ? and user_id = ?", head.ID, targetUserId).Find(&children).Error
		if err != nil {
			logs.ErrorLogger.Error("查询节点失败",
				zap.String("aliasId", aliasId.MarshalBase64()),
				zap.String("targetUserId", targetUserId.MarshalBase64()),
				zap.String("requestUserId", requestUserId.MarshalBase64()),
				zap.Error(err))
			return nil, cerrors.NewSQLError(http.StatusBadRequest, "查询节点失败", err)
		}

		//将每层的数据写入队列
		queue = append(queue, children...)
	}

	return aliasItems, nil
}

func (s *ServiceImpl) buildNeedSavedTree(aliasId id.UUID, aliasSaveRootId id.UUID, aliasItems []models.FileAlias, userId id.UUID) (tree []*FileAliasNode) {
	// 构建需要被保存目录哈希表
	nodeMap := make(map[id.UUID]*FileAliasNode)
	root := aliasItems[0].ParentID
	for _, alias := range aliasItems {
		nodeMap[alias.ID] = &FileAliasNode{FileAlias: alias, Children: make([]*FileAliasNode, 0), IsFile: !alias.IsDirectory}
		if alias.ID == aliasId {
			root = alias.ParentID
		}
	}

	// / 构建需要被保存目录的树型结构
	tree = make([]*FileAliasNode, 0)
	for _, v := range aliasItems {
		node := nodeMap[v.ID]
		node.FileAlias.UserID = userId
		parentId := v.ParentID

		// 当前节点为根节点,直接加入树的根中
		if parentId == root {
			tree = append(tree, node)
			node.Father = &FileAliasNode{FileAlias: models.FileAlias{ID: aliasSaveRootId}}
			continue
		}

		parentNode, exists := nodeMap[parentId]
		// 父节点不存在,跳过构建此节点
		if !exists {
			continue
		}
		// 设置当前节点的父节点为parentNode
		parentNode.Children = append(parentNode.Children, node)
		node.Father = parentNode
	}
	return tree
}

func (s *ServiceImpl) cleanFailChunks(ctx context.Context, path []string, fileId id.UUID) {

	// 1. 删除物理分片文件
	for _, chunk := range path {
		if err := os.Remove(chunk); err != nil && !os.IsNotExist(err) {
			logs.ErrorLogger.Warn("删除分片文件失败",
				zap.String("path", chunk),
				zap.String("fileId", fileId.MarshalBase64()),
				zap.Error(err))
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

func (s *ServiceImpl) writeContentToFile(content []byte, hash string, requestId string) (string, error) {
	dirPath, _ := filepath.Abs(config.Conf.FileConfig.FileStorePosition)

	path := filepath.Join(dirPath, hash)
	path = filepath.Clean(path)

	// 序列化写入文件
	os.MkdirAll(dirPath, 0755)
	file, err := os.Create(path)
	if err != nil {
		logs.ErrorLogger.Error("创建文件失败",
			zap.String("requestId", requestId),
			zap.String("path", path),
			zap.String("fileHash", hash),
			zap.Error(err))
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "创建文件失败", requestId, err)
	}

	defer file.Close()

	// 写入文件内容
	if _, err = file.Write(content); err != nil {
		logs.ErrorLogger.Error("写入分片内容失败",
			zap.String("requestId", requestId),
			zap.String("path", path),
			zap.String("filehash", hash),
			zap.Error(err))
		return "", cerrors.NewCommonError(http.StatusInternalServerError, "写入分片失败", requestId, err)
	}

	return path, nil
}

func (s *ServiceImpl) readFile(path string, hash string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	file, err := os.Open(cleanPath)
	if err != nil {
		logs.ErrorLogger.Error("打开文件失败",
			zap.String("path", cleanPath),
			zap.String("fileHash", hash),
			zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "打开文件失败", "", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		logs.ErrorLogger.Error("读取文件失败",
			zap.String("path", cleanPath),
			zap.String("fileHash", hash),
			zap.Error(err))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "读取文件失败", "", err)
	}

	if toMd5.ContentToMd5(content) != hash {
		logs.ErrorLogger.Error("文件损坏,无法读取",
			zap.String("path", cleanPath),
			zap.String("fileHash", hash))
		return nil, cerrors.NewCommonError(http.StatusInternalServerError, "文件损坏,无法读取", "", err)
	}

	return content, nil
}

func (s *ServiceImpl) uploadToLocal(ctx context.Context, fileId id.UUID, chunkIndex uint64, content []byte, chunkHash string, requestId string) (verify bool, requestID string, err error) {

	path, err := s.writeContentToFile(content, chunkHash, requestId)

	if err != nil {
		return false, requestId, err
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
		logs.ErrorLogger.Error("数据库记录分片错误",
			zap.String("requestId", requestId),
			zap.String("fileId", fileId.MarshalBase64()),
			zap.String("chunkHash", chunkHash),
			zap.Uint64("chunkIndex", chunkIndex),
			zap.Error(err))
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
		logs.ErrorLogger.Error("数据库记录分片序号错误",
			zap.String("requestId", requestId),
			zap.String("fileId", fileId.MarshalBase64()),
			zap.String("chunkHash", chunkHash),
			zap.Uint64("chunkIndex", chunkIndex),
			zap.Error(err))
		return false, requestId, cerrors.NewCommonError(http.StatusInternalServerError, "写入记录失败", requestId, err)
	}

	tx.Commit()

	return true, requestId, nil
}

func (s *ServiceImpl) verifyFile(ctx context.Context, fileId id.UUID) (VerifyFile, error) {

	// 校验文件是否存在
	f := models.File{}
	s.DB.Model(&models.File{}).Where("id = ?", fileId).First(&f)
	if f.ID.IsZero() || f.FileHash == "" {
		logs.ErrorLogger.Error("文件不存在", zap.String("fileId", fileId.MarshalBase64()))
		return VerifyFile{}, cerrors.NewSQLError(http.StatusBadRequest, "文件不存在", nil)
	}

	// 如果文件状态为正常存储就直接返回
	if f.Status == MERGESTORE || f.Status == CHUNKSTORE {
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
		logs.ErrorLogger.Error("查询失败",
			zap.String("fileId", fileId.MarshalBase64()),
			zap.Error(err))
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

	var hash string

	if f.StoreType == 2 {
		//阿里云存储

	} else {
		//本地存储
		hash, err = toMd5.ChunksToMd5(path)
	}

	if err != nil {
		logs.ErrorLogger.Error("校验出错",
			zap.String("fileId", fileId.MarshalBase64()),
			zap.Error(err))
		return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, cerrors.NewSQLError(http.StatusInternalServerError, "校验出错", err)
	}

	// 校验分片hash
	if hash != f.FileHash {
		s.cleanFailChunks(ctx, path, fileId)
		logs.ErrorLogger.Error("分片传输出错",
			zap.String("fileId", fileId.MarshalBase64()),
			zap.String("hash", hash))
		return VerifyFile{File: f}, cerrors.NewSQLError(http.StatusNoContent, "分片传输出错,请重试", nil)
	}

	if err = s.DB.Model(&models.File{}).Where("id = ?", fileId).Update("status", 3).Error; err != nil {
		logs.ErrorLogger.Error("修改文件状态错误",
			zap.String("fileId", fileId.MarshalBase64()),
			zap.Error(err))
		return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, cerrors.NewSQLError(http.StatusInternalServerError, "修改文件状态错误", err)
	}

	return VerifyFile{File: f, NeedChunk: make([]uint64, 0)}, nil
}
