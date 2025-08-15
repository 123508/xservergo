package main

import (
	"fmt"
	user "github.com/123508/xservergo/kitex_gen/user/userservice"
	"github.com/123508/xservergo/pkg/config"
	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/kitex/middleware"
	"github.com/cloudwego/kitex/pkg/limiter"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"github.com/cloudwego/kitex/server"
	etcd "github.com/kitex-contrib/registry-etcd"
	"log"
	"net"
	"time"
)

func main() {
	mysqlDB, err := db.InitMySQLDB()

	if err != nil {
		log.Println(err.Error())
	}

	redisDB, err := db.InitRedisDB()

	if err != nil {
		log.Println(err.Error())
	}

	if mysqlDB != nil && redisDB != nil {
		fmt.Println("数据库初始化成功")
	}

	r, err := etcd.NewEtcdRegistryWithAuth(config.Conf.EtcdConfig.Endpoints, config.Conf.EtcdConfig.Username, config.Conf.EtcdConfig.Password)

	if err != nil {
		log.Fatal(err)
	}

	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", config.Conf.UserConfig.Host, config.Conf.UserConfig.Port))
	svr := user.NewServer(NewUserServiceImpl(mysqlDB, redisDB),
		server.WithServiceAddr(addr),
		server.WithRegistry(r),
		server.WithServerBasicInfo(
			&rpcinfo.EndpointBasicInfo{
				ServiceName: config.Conf.UserConfig.ServiceName,
			},
		),
		server.WithReadWriteTimeout(30*time.Second),                      // 增加读写超时时间
		server.WithMaxConnIdleTime(30*time.Second),                       // 最大空闲时间
		server.WithConnectionLimiter(limiter.NewConnectionLimiter(1000)), // 提高并发处理数
		server.WithErrorHandler(middleware.ErrorLogHandler),
		server.WithMiddleware(middleware.AccessLogHandler),
	)

	err = svr.Run()

	if err != nil {
		log.Println(err.Error())
	}
}
