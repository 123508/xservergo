package db

import (
	"context"
	"fmt"
	"github.com/123508/xservergo/pkg/config"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func InitMySQLDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Conf.MySQLConfig.User,
		config.Conf.MySQLConfig.Password,
		config.Conf.MySQLConfig.Host,
		config.Conf.MySQLConfig.Port,
		config.Conf.MySQLConfig.DBName,
	)
	DB, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := DB.DB()

	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(config.Conf.MySQLConfig.MaxOpenConns) // 设置最大打开连接数
	sqlDB.SetMaxIdleConns(config.Conf.MySQLConfig.MaxIdleConns) // 设置最大空闲连接数

	return DB, nil
}

func InitRedisDB() (*redis.Client, error) {
	RDB := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Conf.RedisConfig.Host, config.Conf.RedisConfig.Port),
		Password: config.Conf.RedisConfig.Password,
		DB:       0,
		PoolSize: config.Conf.RedisConfig.PoolSize,
	})

	_, err := RDB.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}
	return RDB, nil
}

var Rds, _ = InitRedisDB()
