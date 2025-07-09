package logs

import (
	"fmt"
	"github.com/123508/xservergo/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 日志级别映射表
var levelMap = map[string]zapcore.Level{
	"debug":  zapcore.DebugLevel,
	"info":   zapcore.InfoLevel,
	"warn":   zapcore.WarnLevel,
	"error":  zapcore.ErrorLevel,
	"dpanic": zapcore.DPanicLevel,
	"panic":  zapcore.PanicLevel,
	"fatal":  zapcore.FatalLevel,
}

var AccessLogger *zap.Logger

func init() {
	initLogger()
}

func initLogger() {
	// 创建核心列表
	var cores []zapcore.Core

	// 控制台核心（支持显式禁用）
	if shouldEnableStdOut() {
		if consoleCore, err := createConsoleCore(); err == nil {
			cores = append(cores, consoleCore)
		} else {
			fmt.Printf("控制台日志初始化失败: %v\n", err)
		}
	}

	// 文件核心（支持显式禁用）
	if shouldEnableFileOutput() {
		if fileCore, err := createFileCore(); err == nil {
			cores = append(cores, fileCore)
		} else {
			fmt.Printf("文件日志初始化失败: %v\n", err)
		}
	}

	// 确保至少有一个核心
	if len(cores) == 0 {
		fmt.Println("所有日志输出已禁用，启用无操作日志器")
		cores = append(cores, zapcore.NewNopCore())
	}

	// 创建组合核心
	teeCore := zapcore.NewTee(cores...)
	sample := getSamplerConfig()

	// 添加采样
	sampledCore := zapcore.NewSamplerWithOptions(
		teeCore,
		time.Second,
		sample.first,
		sample.thereafter,
	)

	// 创建最终logger
	AccessLogger = zap.New(sampledCore,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
	)
}

// 判断是否启用控制台日志
func shouldEnableStdOut() bool {
	// 配置不存在或显式启用
	return config.Conf.LoggerConfig == nil ||
		config.Conf.LoggerConfig.StdOut == nil ||
		config.Conf.LoggerConfig.StdOut.Allowed
}

// 判断是否启用文件日志
func shouldEnableFileOutput() bool {
	// 配置不存在或显式启用
	return config.Conf.LoggerConfig == nil ||
		config.Conf.LoggerConfig.FileOutput == nil ||
		config.Conf.LoggerConfig.FileOutput.Allowed
}

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

func createConsoleCore() (zapcore.Core, error) {
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.Lock(os.Stdout),
		getLogLevel("console", zapcore.InfoLevel),
	), nil
}

func createFileCore() (zapcore.Core, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	lumberJackLogger, err := createLumberJackLogger()
	if err != nil {
		return nil, fmt.Errorf("文件日志器创建失败: %w", err)
	}

	return zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(lumberJackLogger),
		getLogLevel("file", zapcore.InfoLevel),
	), nil
}

func createLumberJackLogger() (*lumberjack.Logger, error) {
	// 默认配置
	lumberJackLogger := &lumberjack.Logger{
		Filename:   "./log/access.log",
		MaxSize:    128,
		MaxAge:     30,
		MaxBackups: 30,
		LocalTime:  true,
		Compress:   false,
	}

	// 应用配置覆盖
	if config.Conf.LoggerConfig != nil && config.Conf.LoggerConfig.FileOutput != nil {
		fileCfg := config.Conf.LoggerConfig.FileOutput

		if fileCfg.AccessPath != "" {
			lumberJackLogger.Filename = fileCfg.AccessPath
			// 自动添加后缀（如果需要）
			if !strings.HasSuffix(lumberJackLogger.Filename, ".log") {
				lumberJackLogger.Filename += ".log"
			}
		}

		if fileCfg.MaxSize > 0 {
			lumberJackLogger.MaxSize = fileCfg.MaxSize
		}
		if fileCfg.MaxBackups > 0 {
			lumberJackLogger.MaxBackups = fileCfg.MaxBackups
		}
		if fileCfg.MaxAge > 0 {
			lumberJackLogger.MaxAge = fileCfg.MaxAge
		}
		lumberJackLogger.Compress = fileCfg.Compress
	}

	// 确保目录存在
	if err := ensureLogDir(lumberJackLogger.Filename); err != nil {
		// 尝试回退到安全路径
		fallback := "./log/access.log"
		fmt.Printf("日志目录创建失败: %v, 尝试回退到: %s\n", err, fallback)

		if fallbackErr := ensureLogDir(fallback); fallbackErr != nil {
			return nil, fmt.Errorf("回退路径创建失败: %w", fallbackErr)
		}
		lumberJackLogger.Filename = fallback
	}

	return lumberJackLogger, nil
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

// 获取动态日志级别
func getLogLevel(loggerType string, defaultLevel zapcore.Level) zapcore.Level {
	if config.Conf.LoggerConfig == nil {
		return defaultLevel
	}

	var levelStr string
	switch loggerType {
	case "console":
		if config.Conf.LoggerConfig.StdOut == nil {
			return defaultLevel
		}
		levelStr = config.Conf.LoggerConfig.StdOut.Level
	case "file":
		if config.Conf.LoggerConfig.FileOutput == nil {
			return defaultLevel
		}
		levelStr = config.Conf.LoggerConfig.FileOutput.Level
	default:
		return defaultLevel
	}

	if level, ok := levelMap[strings.ToLower(levelStr)]; ok {
		return level
	}
	return defaultLevel
}
