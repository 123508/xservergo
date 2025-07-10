package logs

import (
	"fmt"
	"github.com/123508/xservergo/pkg/config"
	"os"
	"path/filepath"
)

// 获取采样配置
type samplerConfig struct {
	first, thereafter int
}

func getSamplerConfig() samplerConfig {
	cfg := samplerConfig{
		first:      100,
		thereafter: 200,
	}

	if config.Conf.LoggerConfig != nil {
		if config.Conf.LoggerConfig.SampleInitial > 0 {
			cfg.first = config.Conf.LoggerConfig.SampleInitial
		}
		if config.Conf.LoggerConfig.SampleBurst > 0 {
			cfg.thereafter = config.Conf.LoggerConfig.SampleBurst
		}
	}
	return cfg
}

// 确保日志目录存在
func ensureLogDir(filePath string) error {
	dir := filepath.Dir(filePath)
	if dir == "" || dir == "." {
		return nil // 当前目录无需创建
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建日志目录'%s'失败: %w", dir, err)
	}
	return nil
}
