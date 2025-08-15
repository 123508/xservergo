package main

import (
	"context"
	"fmt"
	user "github.com/123508/xservergo/kitex_gen/user/userservice"
	"github.com/123508/xservergo/pkg/config"
	db "github.com/123508/xservergo/pkg/database"
	"github.com/cloudwego/kitex/pkg/endpoint"
	"github.com/cloudwego/kitex/pkg/limiter"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"github.com/cloudwego/kitex/server"
	etcd "github.com/kitex-contrib/registry-etcd"
	"log"
	"net"
	"reflect"
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
		//server.WithMiddleware(canAccessMW),
	)

	err = svr.Run()

	if err != nil {
		log.Println(err.Error())
	}
}

func canAccessMW(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, request, response interface{}) error {
		// 从context中获取RPC信息
		ri := rpcinfo.GetRPCInfo(ctx)
		if ri != nil {
			methodName := ri.To().Method()       // 获取方法名
			serviceName := ri.To().ServiceName() // 获取服务名
			fmt.Println(methodName, serviceName)
			fmt.Println(ri)
		}

		value := reflect.ValueOf(ctx)

		fmt.Println(value)
		fmt.Println(value.FieldByName("userId"))

		err := next(ctx, request, response)
		fmt.Println(response)
		return err
	}
}
