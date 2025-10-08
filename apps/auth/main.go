package main

import (
	"fmt"
	"log"
	"net"

	authserver "github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/pkg/config"
	db "github.com/123508/xservergo/pkg/database"
	"github.com/cloudwego/kitex/pkg/rpcinfo"
	"github.com/cloudwego/kitex/server"
	etcd "github.com/kitex-contrib/registry-etcd"
)

//func canAccessMW(next endpoint.Endpoint) endpoint.Endpoint {
//	return func(ctx context.Context, request, response interface{}) error {
//		// 从context中获取RPC信息
//		ri := rpcinfo.GetRPCInfo(ctx)
//		if ri != nil {
//			//methodName := ri.To().Method()       // 获取方法名
//			//serviceName := ri.To().ServiceName() // 获取服务名
//			//// 通过反射获取request_user_id
//			//v := reflect.ValueOf(request)
//			//requestUserIdField := v.Elem().FieldByName("Req").Elem().FieldByName("RequestUserId")
//			//if requestUserIdField.IsValid() && requestUserIdField.Kind() == reflect.String {
//			//}
//		}
//		s := "{Req.Permission.Code}"
//		// 如果s为{xxx},解析s, 使用反射获取s对应的值
//		v := reflect.ValueOf(request).Elem()
//		if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' {
//			fieldNames := strings.Split(s[1:len(s)-1], ".")
//			for _, fieldName := range fieldNames {
//				v = v.FieldByName(fieldName)
//				// 判断v是否为指针
//				if v.Kind() == reflect.Ptr {
//					if v.IsNil() {
//						return fmt.Errorf("field %s is nil", fieldName)
//					}
//					v = v.Elem() // 获取指针指向的值
//				}
//			}
//			if v.IsValid() && v.Kind() == reflect.String {
//				s = v.String() // 获取到的值
//			}
//		}
//		fmt.Println(s)
//
//		err := next(ctx, request, response)
//		return err
//	}
//}

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
