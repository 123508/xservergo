package logs

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"time"
)

var ErrorLogger *zap.Logger

func init() {
	initErrorLogger()
}

func initErrorLogger() {
	// 创建核心列表
	var cores []zapcore.Core

	// 文件核心
	if fileCore, err := createErrorCore(); err == nil {
		cores = append(cores, fileCore)
	} else {
		fmt.Printf("文件日志初始化失败: %v\n", err)
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
	ErrorLogger = zap.New(sampledCore,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
	)
}

func createErrorCore() (zapcore.Core, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	errorPath := "./log/error.log"

	lumberJackLogger := &lumberjack.Logger{
		Filename:   errorPath,
		MaxSize:    128,
		MaxAge:     30,
		MaxBackups: 30,
		LocalTime:  true,
		Compress:   false,
	}

	if err := ensureLogDir(errorPath); err != nil {
		return nil, fmt.Errorf("错误目录创建失败: %v\n", err)
	}

	return zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(lumberJackLogger),
		getLogLevel("file", zapcore.ErrorLevel),
	), nil
}
