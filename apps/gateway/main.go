package main

import (
	"fmt"
	"github.com/123508/xservergo/apps/gateway/handlers/auth"
	"github.com/123508/xservergo/apps/gateway/handlers/user"
	"github.com/123508/xservergo/apps/gateway/middleware"
	"github.com/123508/xservergo/pkg/config"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	// 启动 Prometheus metrics 服务器
	go func() {
		defer wg.Done()
		metricsAddr := fmt.Sprintf("%s:%d", config.Conf.HertzConfig.Host, 10000)
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("Prometheus metrics server starting on %s", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			log.Printf("Prometheus metrics server error: %v", err)
		}
	}()

	// 启动主服务
	go func() {
		defer wg.Done()
		hertzAddr := fmt.Sprintf("%s:%d", config.Conf.HertzConfig.Host, config.Conf.HertzConfig.Port)
		hz := server.New(server.WithHostPorts(hertzAddr))

		// 注册 Prometheus 中间件
		middleware.RegisterPrometheus(hz)
		// 注册JWT中间件
		hz.Use(middleware.ParseToken())

		// 用户服务
		userGroup := hz.Group("/user")
		userGroup.POST("/register", user.Register)
		userGroup.POST("/login", user.Login)

		// 认证服务
		authGroup := hz.Group("/auth")
		authGroup.POST("create_permission", auth.CreatePermission)

	}()

	// 等待所有服务启动
	wg.Wait()
}
