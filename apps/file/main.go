package main

import (
	"fmt"
	"log"
	"net"
	"time"

	file "github.com/123508/xservergo/kitex_gen/file/fileservice"
	"github.com/123508/xservergo/pkg/config"
	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/kitex/middleware"
	"github.com/123508/xservergo/pkg/util/urds"
	"github.com/cloudwego/kitex/pkg/limiter"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"github.com/cloudwego/kitex/server"
	etcd "github.com/kitex-contrib/registry-etcd"
)

func main() {

	//p := provider.NewOpenTelemetryProvider(
	//	provider.WithServiceName(config.Conf.FileConfig.ServiceName), // 服务名
	//	provider.WithExportEndpoint("localhost:4317"),                // OTLP上报地址（若使用Jaeger，可改为"localhost:14250"）
	//	provider.WithInsecure(),                                      // 是否使用不安全连接（默认true）
	//)
	//defer p.Shutdown(context.Background())

	r, err := etcd.NewEtcdRegistryWithAuth(config.Conf.EtcdConfig.Endpoints, config.Conf.EtcdConfig.Username, config.Conf.EtcdConfig.Password)

	if err != nil {
		log.Fatal(err)
	}

	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", config.Conf.FileConfig.Host, config.Conf.FileConfig.Port))
	svr := file.NewServer(NewFileService(mysqlDB, redisDB, urds.DevEnv),
		server.WithServiceAddr(addr),
		server.WithRegistry(r),
		server.WithServerBasicInfo(
			&rpcinfo.EndpointBasicInfo{
				ServiceName: config.Conf.FileConfig.ServiceName,
			},
		),
		server.WithReadWriteTimeout(30*time.Second),                      // 增加读写超时时间
		server.WithMaxConnIdleTime(30*time.Second),                       // 最大空闲时间
		server.WithConnectionLimiter(limiter.NewConnectionLimiter(1000)), // 提高并发处理数
		server.WithErrorHandler(middleware.ErrorLogHandler),
		server.WithMiddleware(middleware.AccessLogHandler),
		//server.WithSuite(tracing.NewServerSuite()),
	)

	err = svr.Run()

	if err != nil {
		log.Println(err.Error())
	}

}
