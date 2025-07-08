# XServerGo 微服务项目

基于 CloudWeGo Kitex 和 Hertz 框架构建的微服务项目，采用 gRPC 通信，使用 Proto3 定义接口。

## 项目架构

```
xservergo/
├── apps/                  # 应用程序入口
│   ├── gateway/           # API网关 (Hertz)
│   └── user/              # 用户服务 (Kitex)
├── idl/                   # Proto3 接口定义
├── kitex_gen/             # Kitex生成的代码
├── pkg/                   # 公共库
├── scripts/               # 脚本文件
├── go.mod                 # Go模块定义
└── README.md              # 项目说明文档
```
