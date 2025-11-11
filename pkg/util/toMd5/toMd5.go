package toMd5

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// ChunksToMd5 并发计算文件哈希（适用于大量小文件）
func ChunksToMd5(filePaths []string) (string, error) {

	hasher := md5.New()

	// 按顺序处理每个分片文件
	for _, filePath := range filePaths {
		// 确保路径格式统一
		cleanPath := filepath.Clean(filePath)

		// 打开分片文件
		file, err := os.Open(cleanPath)
		if err != nil {
			return "", fmt.Errorf("打开文件 %s 失败: %v", cleanPath, err)
		}

		// 将文件内容流式写入哈希计算器
		_, err = io.Copy(hasher, file)
		file.Close() // 立即关闭文件

		if err != nil {
			return "", fmt.Errorf("读取文件 %s 失败: %v", cleanPath, err)
		}
	}

	// 计算最终哈希值
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

func MergeToFiles(filePaths []string, outputPath string) error {
	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	// 遍历所有文件路径
	for _, filePath := range filePaths {
		// 使用filepath.Clean确保路径格式统一
		cleanPath := filepath.Clean(filePath)

		fmt.Printf("正在合并文件: %s\n", cleanPath)

		// 打开源文件
		srcFile, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("打开文件 %s 失败: %v", cleanPath, err)
		}

		// 使用bufio.Reader提高读取效率
		reader := bufio.NewReader(srcFile)
		bytesCopied, err := io.Copy(writer, reader)
		if err != nil {
			srcFile.Close()
			return fmt.Errorf("复制文件 %s 内容失败: %v", cleanPath, err)
		}

		srcFile.Close()
		fmt.Printf("文件 %s 合并完成，复制了 %d 字节\n", filepath.Base(cleanPath), bytesCopied)
	}

	return nil
}
