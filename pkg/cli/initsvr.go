package cli

import (
	"github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/kitex_gen/user/userservice"
	"github.com/123508/xservergo/pkg/config"
	"github.com/cloudwego/kitex/client"
	"github.com/cloudwego/kitex/pkg/discovery"
	etcd "github.com/kitex-contrib/registry-etcd"
	"time"
)

// initEtcdRegistry 初始化etcd注册中心
func initEtcdRegistry() (discovery.Resolver, error) {
	return etcd.NewEtcdResolverWithAuth(
		config.Conf.EtcdConfig.Endpoints,
		config.Conf.EtcdConfig.Username,
		config.Conf.EtcdConfig.Password,
	)
}

// InitUserService 初始化用户服务客户端
func InitUserService() userservice.Client {
	r, err := initEtcdRegistry()
	if err != nil {
		panic(err)
	}

	c, err := userservice.NewClient(
		config.Conf.UserConfig.ServiceName,
		client.WithRPCTimeout(30*time.Second),
		client.WithResolver(r),
	)
	if err != nil {
		panic(err)
	}

	return c
}

// InitAuthService 初始化认证服务客户端
func InitAuthService() authservice.Client {
	r, err := initEtcdRegistry()
	if err != nil {
		panic(err)
	}

	c, err := authservice.NewClient(
		config.Conf.AuthConfig.ServiceName,
		client.WithRPCTimeout(3*time.Second),
		client.WithResolver(r),
	)
	if err != nil {
		panic(err)
	}

	return c
}
