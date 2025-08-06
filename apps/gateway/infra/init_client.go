package infra

import (
	"github.com/123508/xservergo/pkg/cli"
)

var UserClient = cli.InitUserService()

var AuthClient = cli.InitAuthService()
