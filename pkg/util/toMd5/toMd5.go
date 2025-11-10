package toMd5

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func ContentToMd5(data []byte) string {
	hash := md5.New()
	hash.Write(data) // 直接写入字节切片，避免转换
	return hex.EncodeToString(hash.Sum(nil))
}

func StreamContentToMd5(filePath string, size int) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// 创建带缓冲的读取器
	reader := bufio.NewReader(f)

	hash := md5.New()

	// 使用固定大小的缓冲区
	buffer := make([]byte, size) // 64KB缓冲区

	for {
		bytesRead, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("error reading file: %w", err)
		}

		if bytesRead > 0 {
			hash.Write(buffer[:bytesRead])
		}

		if err == io.EOF {
			break
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
