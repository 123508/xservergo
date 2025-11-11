package service

import "github.com/123508/xservergo/pkg/models"

type VerifyFile struct {
	File      models.File
	NeedChunk []uint64
}
