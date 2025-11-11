package config

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type AppConfig struct {
	*MySQLConfig   `mapstructure:"mysql"`
	*RedisConfig   `mapstructure:"redis"`
	*QRRdisConfig  `mapstructure:"qrredis"`
	*EtcdConfig    `mapstructure:"etcd"`
	*Jwt           `mapstructure:"jwt"`
	*ElasticSearch `mapstructure:"elasticsearch"`
	*HertzConfig   `mapstructure:"hertz"`
	*UserConfig    `mapstructure:"user"`
	*AuthConfig    `mapstructure:"auth"`
	*FileConfig    `mapstructure:"file"`
	*LoggerConfig  `mapstructure:"logger"`
	*AESConfig     `mapstructure:"aes"`
}

type MySQLConfig struct {
	Host         string `mapstructure:"host"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	DBName       string `mapstructure:"dbname"`
	Port         int    `mapstructure:"port"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
}

type RedisConfig struct {
	Host         string `mapstructure:"host"`
	Password     string `mapstructure:"password"`
	Port         int    `mapstructure:"port"`
	DB           int    `mapstructure:"db"`
	PoolSize     int    `mapstructure:"pool_size"`
	MinIdleConns int    `mapstructure:"min_idle_conns"`
}

type QRRdisConfig struct {
	Host         string `mapstructure:"host"`
	Password     string `mapstructure:"password"`
	Port         int    `mapstructure:"port"`
	DB           int    `mapstructure:"db"`
	PoolSize     int    `mapstructure:"pool_size"`
	MinIdleConns int    `mapstructure:"min_idle_conns"`
}

type EtcdConfig struct {
	Endpoints []string `mapstructure:"endpoints"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
}

type Jwt struct {
	AdminSecretKey  string `mapstructure:"admin_secret_key"`
	AccessTokenTTL  int    `mapstructure:"access_token_ttl"`
	RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"`
}

type ElasticSearch struct {
	Hosts    []string `mapstructure:"hosts"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
}

type HertzConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type UserConfig struct {
	Host        string `mapstructure:"host"`
	Port        int    `mapstructure:"port"`
	ServiceName string `mapstructure:"service_name"`
}

type AuthConfig struct {
	Host        string `mapstructure:"host"`
	Port        int    `mapstructure:"port"`
	ServiceName string `mapstructure:"service_name"`
}

type FileConfig struct {
	Host              string `mapstructure:"host"`
	Port              int    `mapstructure:"port"`
	ServiceName       string `mapstructure:"service_name"`
	FileStorePosition string `mapstructure:"file_store_position"`
}

type LoggerConfig struct {
	StdOut        *StdOutConfig     `mapstructure:"stdout"`
	FileOutput    *FileOutputConfig `mapstructure:"file_output"`
	SampleInitial int               `mapstructure:"sample_initial"`
	SampleBurst   int               `mapstructure:"sample_burst"`
}

type StdOutConfig struct {
	Allowed bool   `mapstructure:"allowed"`
	Level   string `mapstructure:"level"`
}

type FileOutputConfig struct {
	Allowed    bool   `mapstructure:"allowed"`
	AccessPath string `mapstructure:"access_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
	Level      string `mapstructure:"level"`
}

type AESConfig struct {
	Key string `mapstructure:"key"`
	IV  string `mapstructure:"iv"`
}

var Conf AppConfig

// setDefaultValues 设置默认配置值，基于docker-compose.yaml中的服务配置
func setDefaultValues(v *viper.Viper) {
	// MySQL 默认配置
	v.SetDefault("mysql.host", "127.0.0.1")
	v.SetDefault("mysql.port", 3306)
	v.SetDefault("mysql.user", "xservergo")
	v.SetDefault("mysql.password", "xservergo")
	v.SetDefault("mysql.dbname", "xservergo")
	v.SetDefault("mysql.max_open_conns", 20)
	v.SetDefault("mysql.max_idle_conns", 20)

	// Redis 默认配置
	v.SetDefault("redis.host", "127.0.0.1")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 100)
	v.SetDefault("redis.min_idle_conns", 10)

	// QRRedis 默认配置
	v.SetDefault("qrredis.host", "127.0.0.1")
	v.SetDefault("qrredis.port", 6380)
	v.SetDefault("qrredis.password", "")
	v.SetDefault("qrredis.db", 0)
	v.SetDefault("qrredis.pool_size", 100)
	v.SetDefault("qrredis.min_idle_conns", 10)

	// Etcd 默认配置
	v.SetDefault("etcd.endpoints", []string{"127.0.0.1:2379"})
	v.SetDefault("etcd.username", "root")
	v.SetDefault("etcd.password", "xservergo")

	// JWT 默认配置
	v.SetDefault("jwt.admin_secret_key", "default_admin_secret_key_change_in_production")
	v.SetDefault("jwt.admin_ttl", 604800) // 7天（秒）
	v.SetDefault("jwt.admin_suv", 3600)   // 1小时（秒）

	// ElasticSearch 默认配置
	v.SetDefault("elasticsearch.hosts", []string{"http://127.0.0.1:9200"})
	v.SetDefault("elasticsearch.username", "")
	v.SetDefault("elasticsearch.password", "")

	// Hertz 默认配置
	v.SetDefault("hertz.host", "127.0.0.1")
	v.SetDefault("hertz.port", 8080)

	// User 服务默认配置
	v.SetDefault("user.host", "127.0.0.1")
	v.SetDefault("user.port", 8900)
	v.SetDefault("user.service_name", "user_service")

	// Auth 服务默认配置
	v.SetDefault("auth.host", "127.0.0.1")
	v.SetDefault("auth.port", 8901)
	v.SetDefault("auth.service_name", "auth_service")

	// File 服务默认配置
	v.SetDefault("file.host", "127.0.0.1")
	v.SetDefault("file.port", 8904)
	v.SetDefault("file.service_name", "file_service")

	// JWT 默认配置
	v.SetDefault("jwt.admin_secret_key", "default_admin_secret_key_change_in_production")
	v.SetDefault("jwt.access_token_ttl", 3600)
	v.SetDefault("jwt.refresh_token_ttl", 604800)

	// Logger 默认配置
	v.SetDefault("logger.stdout.allowed", true)
	v.SetDefault("logger.stdout.level", "info")
	v.SetDefault("logger.file_output.allowed", true)
	v.SetDefault("logger.file_output.access_path", "./log/access.log")
	v.SetDefault("logger.file_output.max_size", 100)
	v.SetDefault("logger.file_output.max_backups", 14)
	v.SetDefault("logger.file_output.max_age", 14)
	v.SetDefault("logger.file_output.compress", false)
	v.SetDefault("logger.file_output.level", "info")
	v.SetDefault("logger.sample_initial", 100)
	v.SetDefault("logger.sample_burst", 200)

	//加密默认设置
	v.SetDefault("aes.key", "bfTbpSMpuYCEOXhmfSejqvoDcpq/W31ofbbqoNHOepA=")
	v.SetDefault("aes.iv", "ZJ3y2hyLva1Qng8Q2iJO7w==")
}

func init() {
	v := viper.New()
	//v.SetConfigFile("config/config.yaml")

	v.AddConfigPath("config")
	v.AddConfigPath("../../config")
	v.SetConfigName("conf")
	v.SetConfigType("yaml")

	// 设置默认值
	setDefaultValues(v)

	err := v.ReadInConfig() // 读取配置信息
	if err != nil {
		fmt.Printf("viper Read Config failed, err:%v\n", err)
		// return
	}

	// 把读取到的配置信息反序列化到 Conf 变量中
	if err := v.Unmarshal(&Conf); err != nil {
		fmt.Printf("viper Unmarshal failed, err:%v\n", err)
	}
	v.WatchConfig() // 对配置文件进行监视，若有改变就重新反序列到Conf中
	v.OnConfigChange(func(in fsnotify.Event) {
		fmt.Println("配置文件修改了...")
		if err := v.Unmarshal(&Conf); err != nil {
			fmt.Printf("viper.Unmarshal failed, err:%v\n", err)
		}
	})
}
