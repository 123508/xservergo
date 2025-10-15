package main

import (
	"context"
	"net/http"
	"path/filepath"

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

func unmarshalUID(ctx context.Context, uid string) (id.UUID, error) {

	if uid == "" || len(uid) == 0 {
		return id.SystemUUID, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数为空")
	}

	Uid := id.NewUUID()
	if err := Uid.UnmarshalBase64(uid); err != nil {
		return id.SystemUUID, cerrors.NewGRPCError(http.StatusBadRequest, "请求参数错误"+err.Error())
	}

	return Uid, nil
}

func marshalUID(ctx context.Context, uid id.UUID) string {
	return uid.MarshalBase64()
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
			Items:     nil,
			RequestId: "",
		}, cerrors.NewGRPCError(http.StatusBadRequest, "请求文件列表为空")
	}

	targetUid, err := unmarshalUID(ctx, req.TargetUserId)
	if err != nil {
		return &file.InitUploadResp{
			Items:     nil,
			RequestId: "",
		}, err
	}

	requestUid, err := unmarshalUID(ctx, req.RequestUserId)

	if err != nil {
		return &file.InitUploadResp{
			Items:     nil,
			RequestId: "",
		}, err
	}

	fileList := make([]models.File, 0)
	for _, item := range req.FileList {

		name := filepath.Base(item.RelativePath)
		path := filepath.Dir(item.RelativePath)

		fileList = append(fileList, models.File{
			FileName: name,
			FileSize: item.FileSize,
			FilePath: path,
			FileMd5:  item.FileMd5,
		})
	}

	md5s, requestId, err := s.fileService.InitFileUpload(ctx, fileList, targetUid, requestUid)

	if err != nil {
		return &file.InitUploadResp{
			Items:     nil,
			RequestId: "",
		}, err
	}

	result := make([]*file.InitUploadResp_RespItem, 0)

	for _, item := range md5s {
		result = append(result, &file.InitUploadResp_RespItem{
			FileMd5:    item.FileMd5,
			FileStatus: item.Status,
		})
	}

	return &file.InitUploadResp{
		Items:     result,
		RequestId: requestId,
	}, nil

}

// UploadChunk implements the FileServiceImpl interface.
func (s *FileServiceImpl) UploadChunk(ctx context.Context, req *file.UploadChunkReq) (resp *file.UploadChunkResp, err error) {
	// TODO: Your code here...
	return
}

// CompleteUpload implements the FileServiceImpl interface.
func (s *FileServiceImpl) CompleteUpload(ctx context.Context, req *file.CompleteUploadReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
}

// FastUpload implements the FileServiceImpl interface.
func (s *FileServiceImpl) FastUpload(ctx context.Context, req *file.FastUploadReq) (resp *file.FileMeta, err error) {
	// TODO: Your code here...
	return
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
