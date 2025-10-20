package main

import (
	"fmt"
	"log"
	"net"

	authserver "github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/pkg/config"
	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/util/initdb"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"github.com/cloudwego/kitex/server"
	etcd "github.com/kitex-contrib/registry-etcd"
)

var authServiceImpl *AuthServiceImpl

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

		code := ""
		// 判断是否存在user权限
		mysqlDB.Raw("select code from permission where code like 'user_%' limit 1;").Scan(&code)
		if code == "" {
			// 插入用户权限数据
			fmt.Println("正在初始化用户权限数据...")
			initdb.InitUserDb()
			fmt.Println("用户权限数据初始化完成。")
		}

		// 判断是否存在auth权限
		code = ""
		mysqlDB.Raw("select code from permission where code like 'auth_%' limit 1;").Scan(&code)
		if code == "" {
			// 插入权限数据
			fmt.Println("正在初始化认证权限数据...")
			initdb.InitAuthDb()
			fmt.Println("认证权限数据初始化完成。")
		}

	}

	r, err := etcd.NewEtcdRegistryWithAuth(config.Conf.EtcdConfig.Endpoints, config.Conf.EtcdConfig.Username, config.Conf.EtcdConfig.Password)

	if err != nil {
		log.Fatal(err)
	}

	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", config.Conf.AuthConfig.Host, config.Conf.AuthConfig.Port))
	authServiceImpl = NewAuthServiceImpl(mysqlDB, redisDB)
	svr := authserver.NewServer(authServiceImpl,
		server.WithServiceAddr(addr),
		server.WithRegistry(r),
		server.WithServerBasicInfo(
			&rpcinfo.EndpointBasicInfo{
				ServiceName: config.Conf.AuthConfig.ServiceName,
			},
		),
		//server.WithMiddleware(middleware.CanAccessMW), // 使用自定义中间件
	)

	err = svr.Run()

	if err != nil {
		log.Println(err.Error())
	}
}
