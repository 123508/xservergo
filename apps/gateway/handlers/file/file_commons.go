package file

type FileItem struct {
	FileContentHash string `json:"file_content_hash"`
	FileSize        uint64 `json:"file_size"`
	FileName        string `json:"file_name"`
	FileId          string `json:"file_id"`
	Status          int32  `json:"status"`
	Total           uint64 `json:"total"`
}
