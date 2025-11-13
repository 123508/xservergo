package service

import (
	"path/filepath"
	"strings"

	"github.com/123508/xservergo/pkg/models"
)

type VerifyFile struct {
	File      models.File
	NeedChunk []uint64
}

// SplitPathToLevels 将路径分割为层级数组
func SplitPathToLevels(path string) []string {
	// 清理路径
	cleanPath := filepath.Clean(path)

	// 处理空路径
	if cleanPath == "." || cleanPath == "" {
		return []string{}
	}

	var levels []string

	// 处理绝对路径的根部分
	if filepath.IsAbs(cleanPath) {
		// 获取卷名
		volume := filepath.VolumeName(cleanPath)
		if volume != "" {
			levels = append(levels, volume+string(filepath.Separator))
			cleanPath = cleanPath[len(volume):]
		} else {
			// Unix系统的根目录
			levels = append(levels, string(filepath.Separator))
			if len(cleanPath) > 1 {
				cleanPath = cleanPath[1:]
			} else {
				cleanPath = ""
			}
		}
	}

	// 如果路径只剩下分隔符或为空
	if cleanPath == "" || cleanPath == string(filepath.Separator) {
		return levels
	}

	// 移除开头和结尾的分隔符
	cleanPath = strings.Trim(cleanPath, string(filepath.Separator))

	// 分割路径
	parts := strings.Split(cleanPath, string(filepath.Separator))
	levels = append(levels, parts...)

	return levels
}
