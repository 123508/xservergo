package file

type FileItem struct {
	FileContentHash string `json:"file_content_hash"`
	FileSize        uint64 `json:"file_size"`
	FileName        string `json:"file_name"`
	FileId          string `json:"file_id"`
	Status          uint64 `json:"status"`
	Total           uint64 `json:"total"`
	FileType        string `json:"file_type"`
	StoreType       uint64 `json:"store_type"`
}

type FileReq struct {
	AliasId string `json:"alias_id"`
}
