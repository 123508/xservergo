package main

import (
	"context"
	"net/http"

	"github.com/123508/xservergo/apps/file/service"
	"github.com/123508/xservergo/kitex_gen/file"
	"github.com/123508/xservergo/pkg/cerrors"
	"github.com/123508/xservergo/pkg/models"
	"github.com/123508/xservergo/pkg/util/id"
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
			FileName: item.FileName,
			FileSize: item.FileSize,
			FileHash: item.FileContentHash,
			Total:    item.Total,
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
		return &file.UploadVerifyResp{}, err
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

// GetUploadUrl implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetUploadUrl(ctx context.Context, req *file.UploadUrlReq) (resp *file.UploadUrlResp, err error) {
	// TODO: Your code here...
	return
}

// RegisterUploadedFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) RegisterUploadedFile(ctx context.Context, req *file.RegisterUploadReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// CreateFolder implements the FileServiceImpl interface.
func (s *FileServiceImpl) CreateFolder(ctx context.Context, req *file.CreateFolderReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// RenameFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) RenameFile(ctx context.Context, req *file.RenameFileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// MoveFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) MoveFile(ctx context.Context, req *file.MoveFileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// CopyFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) CopyFile(ctx context.Context, req *file.CopyFileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// UpdateFilePublic implements the FileServiceImpl interface.
func (s *FileServiceImpl) UpdateFilePublic(ctx context.Context, req *file.UpdateFilePublicReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// TrashFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) TrashFile(ctx context.Context, req *file.FileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// DeleteFilePermanently implements the FileServiceImpl interface.
func (s *FileServiceImpl) DeleteFilePermanently(ctx context.Context, req *file.FileReq) (resp *file.Empty, err error) {
	// TODO: Your code here...
	return
}

// RestoreFile implements the FileServiceImpl interface.
func (s *FileServiceImpl) RestoreFile(ctx context.Context, req *file.FileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// GetTrashedFiles implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetTrashedFiles(ctx context.Context, req *file.UserReq) (resp *file.ListDirectoryResp, err error) {
	// TODO: Your code here...
	return
}

// GetFileMeta implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetFileMeta(ctx context.Context, req *file.FileReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// ListDirectory implements the FileServiceImpl interface.
func (s *FileServiceImpl) ListDirectory(ctx context.Context, req *file.ListDirectoryReq) (resp *file.ListDirectoryResp, err error) {
	// TODO: Your code here...
	return
}

// SearchFiles implements the FileServiceImpl interface.
func (s *FileServiceImpl) SearchFiles(ctx context.Context, req *file.SearchFilesReq) (resp *file.SearchFilesResp, err error) {
	// TODO: Your code here...
	return
}

// GetPreviewUrl implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetPreviewUrl(ctx context.Context, req *file.FileReq) (resp *file.PreviewResp, err error) {
	// TODO: Your code here...
	return
}

// GetTranscodeStatus implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetTranscodeStatus(ctx context.Context, req *file.FileReq) (resp *file.TranscodeStatusResp, err error) {
	// TODO: Your code here...
	return
}

// GenerateDocumentPreview implements the FileServiceImpl interface.
func (s *FileServiceImpl) GenerateDocumentPreview(ctx context.Context, req *file.FileReq) (resp *file.PreviewResp, err error) {
	// TODO: Your code here...
	return
}

// CleanExpiredTrash implements the FileServiceImpl interface.
func (s *FileServiceImpl) CleanExpiredTrash(ctx context.Context, req *file.CleanTrashReq) (resp *file.CleanTrashResp, err error) {
	// TODO: Your code here...
	return
}

// GetStorageQuota implements the FileServiceImpl interface.
func (s *FileServiceImpl) GetStorageQuota(ctx context.Context, req *file.UserReq) (resp *file.StorageQuotaResp, err error) {
	// TODO: Your code here...
	return
}

// DeduplicateFiles implements the FileServiceImpl interface.
func (s *FileServiceImpl) DeduplicateFiles(ctx context.Context, req *file.UserReq) (resp *file.DeduplicationResp, err error) {
	// TODO: Your code here...
	return
}
