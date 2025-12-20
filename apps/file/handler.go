package main

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/file/service"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util/id"
	"github.com/123508/xservergo/pkg/util/validate"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// FileServiceImpl implements the last service interface defined in the IDL.
type FileServiceImpl struct {
	fileService service.FileService
}

func unmarshalUUID(ctx context.Context, uid string) (id.UUID, error) {

	if uid == "" || len(uid) == 0 {
		return id.SystemUUID, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数为空")
	}

	uuid := id.NewUUID()
	if err := uuid.UnmarshalBase64(uid); err != nil {
		return id.SystemUUID, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误"+err.Error())
	}

	return uuid, nil
}

func parseServiceErrToHandlerError(ctx context.Context, err error) (e error) {

	var code uint64
	var message string
	if com, ok := err.(*cerrors.CommonError); ok {
		err = cerrors.NewGRPCError(com.Code, com.Message)
		code = com.Code
		message = com.Message
	} else if sql, ok := err.(*cerrors.SQLError); ok {
		err = cerrors.NewGRPCError(sql.Code, sql.Message)
		code = sql.Code
		message = sql.Message
	} else {
		code = http.StatusInternalServerError
		message = "服务器异常,操作失败"
	}

	return cerrors.NewGRPCError(code, message)
}

func NewFileService(database *gorm.DB, rds *redis.Client, env string) *FileServiceImpl {
	return &FileServiceImpl{
		fileService: service.NewService(database, rds, env),
	}
}

// InitUpload implements the FileServiceImpl interface.
func (s *FileServiceImpl) InitUpload(ctx context.Context, req *file.InitUploadReq) (resp *file.InitUploadResp, err error) {
	if req.FileList == nil {
		return &file.InitUploadResp{
			FileStatus: make([]*file.FileItem, 0),
			RequestId:  "",
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求文件列表为空")
	}

	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)

	if err != nil {
		return &file.InitUploadResp{
			FileStatus: make([]*file.FileItem, 0),
			RequestId:  "",
		}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)

	if err != nil {
		return &file.InitUploadResp{
			FileStatus: make([]*file.FileItem, 0),
			RequestId:  "",
		}, err
	}

	fileList := make([]models.File, 0)
	for _, item := range req.FileList {
		fileList = append(fileList, models.File{
			FileName:  item.FileName,
			FileSize:  item.FileSize,
			FileHash:  item.FileContentHash,
			Total:     item.Total,
			FileType:  item.FileType,
			StoreType: item.StoreType,
		})
	}

	files, uploadId, requestId, err := s.fileService.InitFileUpload(ctx, fileList, targetUid, requestUid)

	if err != nil {
		return &file.InitUploadResp{
			FileStatus: make([]*file.FileItem, 0),
			RequestId:  "",
		}, parseServiceErrToHandlerError(ctx, err)
	}

	fileStatus := make([]*file.FileItem, len(files))

	for i, item := range files {
		fileStatus[i] = &file.FileItem{
			FileName: item.FileName,
			FileId:   item.ID.MarshalBase64(),
			Status:   item.Status,
		}
	}

	return &file.InitUploadResp{
		FileStatus: fileStatus,
		UploadId:   uploadId,
		RequestId:  requestId,
	}, nil

}

// UploadChunk implements the FileServiceImpl interface.
func (s *FileServiceImpl) UploadChunk(ctx context.Context, req *file.UploadChunkReq) (resp *file.UploadChunkResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.UploadChunkResp{
			ChunkIndex: 0,
			Verified:   false,
			RequestId:  "",
		}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)

	if err != nil {
		return &file.UploadChunkResp{
			ChunkIndex: 0,
			Verified:   false,
			RequestId:  "",
		}, err
	}

	fileUid, err := unmarshalUUID(ctx, req.FileId)

	if err != nil {
		return &file.UploadChunkResp{
			ChunkIndex: 0,
			Verified:   false,
			RequestId:  "",
		}, err
	}

	ok, requestId, err := s.fileService.UploadChunk(ctx, fileUid, req.ChunkIndex, req.UploadId, req.ChunkContent, req.ChunkContentHash, req.RequestId, targetUid, requestUid)

	if err != nil {
		return &file.UploadChunkResp{
			ChunkIndex: 0,
			Verified:   false,
			RequestId:  "",
		}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.UploadChunkResp{
		ChunkIndex: req.ChunkIndex,
		Verified:   ok,
		RequestId:  requestId,
	}, err
}

// UploadVerify implements the FileServiceImpl interface.
func (s *FileServiceImpl) UploadVerify(ctx context.Context, req *file.UploadVerifyReq) (resp *file.UploadVerifyResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.UploadVerifyResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)

	if err != nil {
		return &file.UploadVerifyResp{}, err
	}

	fileId := make([]id.UUID, 0)
	failFileId := make([]string, 0)

	for _, item := range req.FileId {
		fileUid, err := unmarshalUUID(ctx, item)
		if err != nil {
			failFileId = append(failFileId, item)
			continue
		}
		fileId = append(fileId, fileUid)
	}

	files, err := s.fileService.UploadVerify(ctx, fileId, req.RequestId, req.UploadId, targetUid, requestUid)

	if err != nil {
		return &file.UploadVerifyResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	result := make([]*file.UploadVerifyFile, len(files))

	for i, item := range files {
		result[i] = &file.UploadVerifyFile{
			File: &file.FileItem{
				FileContentHash: item.File.FileHash,
				FileSize:        item.File.FileSize,
				FileName:        item.File.FileName,
				FileId:          item.File.ID.MarshalBase64(),
				Status:          item.File.Status,
			},
			NeedIndex: item.NeedChunk,
		}
	}

	return &file.UploadVerifyResp{
		Files:      result,
		FailFileId: failFileId,
	}, nil
}

// DirectUpload implements the FileServiceImpl interface.
func (s *FileServiceImpl) DirectUpload(ctx context.Context, req *file.DirectUploadReq) (resp *file.DirectUploadResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.DirectUploadResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)

	if err != nil {
		return &file.DirectUploadResp{}, err
	}

	f := models.File{
		FileHash:  req.File.FileContentHash,
		FileSize:  req.File.FileSize,
		FileName:  req.File.FileName,
		Total:     1,
		FileType:  req.File.FileType,
		StoreType: req.File.StoreType,
	}

	result, err := s.fileService.DirectUpload(ctx, f, req.Content, targetUid, requestUid)

	if err != nil {
		return &file.DirectUploadResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.DirectUploadResp{
		File: &file.FileItem{
			FileName: result.FileName,
			FileId:   result.ID.MarshalBase64(),
			Status:   result.Status,
		},
	}, nil
}

// TransferSave implements the FileServiceImpl interface.
func (s *FileServiceImpl) TransferSave(ctx context.Context, req *file.TransferSaveReq) (resp *file.TransferSaveResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.TransferSaveResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.TransferSaveResp{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.TransferSaveResp{}, err
	}

	aliasSaveRootId, err := unmarshalUUID(ctx, req.AliasSaveRootId)
	if err != nil {
		return &file.TransferSaveResp{}, err
	}

	needSelect := false
	if req.SelectedFileIds == nil {
		needSelect = true
	}
	selectIds := make([]id.UUID, 0)
	for _, v := range req.SelectedFileIds {
		fid, err := unmarshalUUID(ctx, v)
		if err != nil {
			return &file.TransferSaveResp{}, err
		}
		selectIds = append(selectIds, fid)
	}

	reflectFiles, requestId, err := s.fileService.TransferSave(ctx, aliasId, aliasSaveRootId, needSelect, req.ResolutionStrategy, selectIds, req.RequestId, targetUid, requestUid)

	if err != nil {
		return &file.TransferSaveResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	// 无冲突,直接返回
	if reflectFiles == nil {
		return &file.TransferSaveResp{
			ReflectExist: false,
		}, nil
	}

	// 不需要自行判断,直接交给前端
	if req.ResolutionStrategy != 6 {
		return &file.TransferSaveResp{
			ReflectExist: true,
		}, nil
	}

	reflects := make([]*file.ReflectFile, len(reflectFiles))
	for i, fid := range reflectFiles {
		reflects[i] = &file.ReflectFile{
			OldFileId: fid.OldFileId.MarshalBase64(),
			NewFileId: fid.OldFileId.MarshalBase64(),
			FileName:  fid.FileName,
		}
	}
	return &file.TransferSaveResp{
		Reflects:     reflects,
		ReflectExist: true,
		RequestId:    requestId,
	}, nil
}

// PreDownLoad implements the FileServiceImpl interface.
func (s *FileServiceImpl) PreDownLoad(ctx context.Context, req *file.PreDownLoadReq) (resp *file.PreDownloadResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.PreDownloadResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.PreDownloadResp{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.PreDownloadResp{}, err
	}

	aliasName, requestId, list, storeType, total, err := s.fileService.PreDownLoad(ctx, aliasId, targetUid, requestUid)

	if err != nil {
		return &file.PreDownloadResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	dm := make([]*file.DownloadMsg, 0)

	for _, v := range list {
		dm = append(dm, &file.DownloadMsg{
			FileId:     v.FileId,
			ChunkId:    v.ChunkId,
			ChunkIndex: v.ChunkIndex,
		})
	}

	return &file.PreDownloadResp{
		RequestId: requestId,
		Type:      storeType,
		Dms:       dm,
		AliasName: aliasName,
		Total:     total,
	}, nil
}

// Download implements the FileServiceImpl interface.
func (s *FileServiceImpl) Download(ctx context.Context, req *file.DownloadReq) (resp *file.DownloadResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.DownloadResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.DownloadResp{}, err
	}

	oneId := id.NewUUID()
	execute := false

	if req.Dm.FileId != "" && req.Type == 4 {
		oneId, err = unmarshalUUID(ctx, req.Dm.FileId)
		if err != nil {
			return &file.DownloadResp{}, err
		}
		execute = true
	}

	if !execute && req.Dm.ChunkId != "" && req.Type == 3 {
		oneId, err = unmarshalUUID(ctx, req.Dm.ChunkId)
		if err != nil {
			return &file.DownloadResp{}, err
		}
		execute = true
	}

	if !execute {
		return &file.DownloadResp{}, cerrors.NewGRPCError(http.StatusBadRequest, "请求错误")
	}

	content, err := s.fileService.Download(ctx, oneId, requestUid, targetUid, req.RequestId, req.Type)

	if err != nil {
		return &file.DownloadResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.DownloadResp{
		Content: content,
	}, nil
}

// CreateFolder implements the FileServiceImpl interface.
func (s *FileServiceImpl) CreateFolder(ctx context.Context, req *file.CreateFolderReq) (resp *file.FileAliasItem, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	parentAliasId, err := unmarshalUUID(ctx, req.ParentAliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	err = validate.IsValidateString(req.FolderName)
	if err != nil {
		return &file.FileAliasItem{}, cerrors.NewGRPCError(http.StatusBadRequest, err.Error())
	}

	fileAlias, err := s.fileService.CreateFolder(ctx, parentAliasId, req.FolderName, req.IsRoot, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// RenameFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) RenameFile(ctx context.Context, req *file.RenameFileReq) (resp *file.FileAliasItem, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	err = validate.IsValidateString(req.NewName)
	if err != nil {
		return &file.FileAliasItem{}, cerrors.NewGRPCError(http.StatusBadRequest, err.Error())
	}

	fileAlias, err := s.fileService.RenameFile(ctx, aliasId, req.NewName, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}
	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		FileId:      fileAlias.FileID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// MoveFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) MoveFile(ctx context.Context, req *file.MoveFileReq) (resp *file.FileAliasItem, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	newParentId, err := unmarshalUUID(ctx, req.NewParentId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}
	fileAlias, err := s.fileService.MoveFile(ctx, aliasId, newParentId, req.IsMoveToRoot, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}
	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		FileId:      fileAlias.FileID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// TrashFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) TrashFile(ctx context.Context, req *file.FileReq) (resp *file.FileAliasItem, err error) {

	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	fileAlias, err := s.fileService.TrashFile(ctx, aliasId, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		FileId:      fileAlias.FileID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// DeleteFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) DeleteFile(ctx context.Context, req *file.FileReq) (resp *file.FileAliasItem, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	fileAlias, err := s.fileService.DeleteFile(ctx, aliasId, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		FileId:      fileAlias.FileID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// RestoreFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) RestoreFile(ctx context.Context, req *file.FileReq) (resp *file.FileAliasItem, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileAliasItem{}, err
	}

	fileAlias, err := s.fileService.RestoreFile(ctx, aliasId, requestUid, targetUid)
	if err != nil {
		return &file.FileAliasItem{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.FileAliasItem{
		AliasId:     fileAlias.ID.MarshalBase64(),
		FileId:      fileAlias.FileID.MarshalBase64(),
		UserId:      req.TargetUserId,
		FileName:    fileAlias.FileName,
		IsDirectory: fileAlias.IsDirectory,
	}, nil
}

// GetFileMeta implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetFileMeta(ctx context.Context, req *file.FileReq) (resp *file.FileMetaResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileMetaResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileMetaResp{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileMetaResp{}, err
	}

	meta, err := s.fileService.GetFileMeta(ctx, aliasId, requestUid, targetUid)

	if err != nil {
		return &file.FileMetaResp{}, parseServiceErrToHandlerError(ctx, err)
	}

	return &file.FileMetaResp{
		IsDirectory:     meta.IsDirectory,
		AliasId:         meta.AliasId,
		FileId:          meta.FileId,
		FileName:        meta.FileName,
		FileContentHash: meta.FileContentHash,
		FileSize:        meta.FileSize,
		Status:          meta.Status,
		FileType:        meta.FileType,
		FileCover:       meta.FileCover,
		CreatedAt:       meta.CreatedAt,
		UpdatedAt:       meta.UpdatedAt,
	}, nil
}

// ListDirectory implements the FileServiceImpl interface.
func (s *FileServiceImpl) ListDirectory(ctx context.Context, req *file.ListDirectoryReq) (resp *file.FileListResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileListResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileListResp{}, err
	}

	aliasId, err := unmarshalUUID(ctx, req.AliasId)
	if err != nil {
		return &file.FileListResp{}, err
	}

	items, total, err := s.fileService.ListDirectory(ctx, aliasId, req.RootType, req.Page, req.PageSize, requestUid, targetUid)
	if err != nil {
		return &file.FileListResp{}, err
	}
	fileRes := make([]*file.FileItem, len(items))
	for i, item := range items {
		fileRes[i] = &file.FileItem{
			FileSize:  item.FileSize,
			FileName:  item.FileName,
			FileId:    item.FileID.MarshalBase64(),
			FileType:  item.FileType,
			FileCover: item.FileCover,
			CreatedAt: item.CreatedAt,
		}
	}
	return &file.FileListResp{
		Files:      fileRes,
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

// SearchFiles implements the FileServiceImpl interface.
func (s *FileServiceImpl) SearchFiles(ctx context.Context, req *file.SearchFilesReq) (resp *file.FileListResp, err error) {
	targetUid, err := unmarshalUUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.FileListResp{}, err
	}

	requestUid, err := unmarshalUUID(ctx, req.RequestUserId)
	if err != nil {
		return &file.FileListResp{}, err
	}

	if err = validate.IsValidateString(req.Keyword); err != nil {
		return &file.FileListResp{}, cerrors.NewGRPCError(http.StatusBadRequest, err.Error())
	}

	items, total, err := s.fileService.SearchFile(ctx, req.Keyword, req.FileType, req.Page, req.PageSize, requestUid, targetUid)

	if err != nil {
		return &file.FileListResp{}, err
	}
	fileRes := make([]*file.FileItem, len(items))
	for i, item := range items {
		fileRes[i] = &file.FileItem{
			FileSize:  item.FileSize,
			FileName:  item.FileName,
			FileId:    item.FileID.MarshalBase64(),
			FileType:  item.FileType,
			FileCover: item.FileCover,
			CreatedAt: item.CreatedAt,
		}
	}
	return &file.FileListResp{
		Files:      fileRes,
		TotalCount: total,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

// BuildSharedUrl implements the FileServiceImpl interface.
func (s *FileServiceImpl) BuildSharedUrl(ctx context.Context, req *file.FileReq) (resp *file.PreviewUrlResp, err error) {
	// TODO: Your code here...
	return
}

// GetTranscodeStatus implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetTranscodeStatus(ctx context.Context, req *file.FileReq) (resp *file.TranscodeStatusResp, err error) {
	// TODO: Your code here...
	return
}

// GenerateFilePreview implements the FileServiceImpl interface.
func (s *FileServiceImpl) GenerateFilePreview(ctx context.Context, req *file.FileReq) (resp *file.PreviewUrlResp, err error) {
	// TODO: Your code here...
	return
}

// CleanTrash implements the FileServiceImpl interface.
func (s *FileServiceImpl) CleanTrash(ctx context.Context, req *file.CleanTrashReq) (resp *file.CleanTrashResp, err error) {
	// TODO: Your code here...
	return
}

// GetStorageQuota implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetStorageQuota(ctx context.Context, req *file.StorageQuotaReq) (resp *file.StorageQuotaResp, err error) {
	// TODO: Your code here...
	return
}
