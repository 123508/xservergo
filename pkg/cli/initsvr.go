package cli

import (
	"github.com/123508/xservergo/kitex_gen/auth/authservice"
	"github.com/123508/xservergo/kitex_gen/user/userservice"
	"github.com/cloudwego/kitex/client"
	"time"
)

func InitUserService() userservice.Client {
	c, err := userservice.NewClient("bitjump.douyinshop.user",
		client.WithHostPorts("127.0.0.1:8902"),
		client.WithRPCTimeout(3*time.Second))

	if err != nil {
		panic(err)
		return nil
	}

	return c
}

func InitAuthService() authservice.Client {
	c, err := authservice.NewClient("bitjump.douyinshop.auth",
		client.WithHostPorts("127.0.0.1:8903"),
		client.WithRPCTimeout(3*time.Second))

	if err != nil {
		panic(err)
		return nil
	}

	return c
}
