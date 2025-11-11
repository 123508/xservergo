package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/util/urds"
	"github.com/cloudwego/hertz/pkg/app"
	"go.uber.org/zap"
)

func RateLimit() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		api := strings.ToLower(fmt.Sprintf("type:%s uri:%s", c.Request.Method(), string(c.URI().Path())))
		userId, ok := ctx.Value("userId").(string)
		//没有userId是无效请求,直接丢弃
		if !ok {
			logs.ErrorLogger.Error("请求无效,丢弃", zap.String("api", api))
			c.Abort()
			return
		}

		ctrl := NewRateLimitCtrl(userId, api)

		if !ctrl.CanAccessAndRateLimit() {
			logs.ErrorLogger.Error("请求被限速,丢弃", zap.String("api", api), zap.String("userId", userId))
			fmt.Println("请求被限速,丢弃")
			c.Abort()
			return
		}

		c.Next(ctx)
	}

}

type RateLimitCtrl struct {
	userId string
	api    string
	ctx    context.Context
}

func NewRateLimitCtrl(userId string, api string) *RateLimitCtrl {
	return &RateLimitCtrl{userId: userId, api: api, ctx: context.Background()}
}

func (r *RateLimitCtrl) CanAccessAndRateLimit() bool {

	rateLimitNumber := apiRateLimitMap[r.api]

	if rateLimitNumber.second <= 0 {
		rateLimitNumber.second = 10
	}
	//-1不限速
	if rateLimitNumber.count == -1 {
		return true
	}

	if rateLimitNumber.count <= 0 {
		rateLimitNumber.count = 200
	}

	key := urds.TakeKey("gateway", "rate-limit", r.userId, r.api)
	timeKey := urds.TakeKey("gateway", "rate-limit-time", r.userId, r.api)

	i, _ := db.Rds.Get(r.ctx, key).Int()

	if err := db.Rds.Get(r.ctx, timeKey).Err(); err != nil { //时间到期,清空限制
		i = 1
		db.Rds.Set(r.ctx, key, i, time.Duration(rateLimitNumber.second)*time.Second)
		db.Rds.Set(r.ctx, timeKey, true, time.Duration(rateLimitNumber.second)*time.Second)
	} else {
		if i >= rateLimitNumber.count { //时间未到期并且超出次数,不允许过
			return false
		} else {
			//时间未到期且未超出数据,允许过
			if err = db.Rds.Get(r.ctx, timeKey).Err(); err == nil {
				i += 1
				db.Rds.Set(r.ctx, key, i, time.Duration(rateLimitNumber.second)*time.Second)
			} else {
				i = 1
				db.Rds.Set(r.ctx, key, i, time.Duration(rateLimitNumber.second)*time.Second)
				db.Rds.Set(r.ctx, timeKey, true, time.Duration(rateLimitNumber.second)*time.Second)
			}
		}
	}

	//fmt.Printf("请求成功,当前限速配置:%+v,当前请求次数:%v\n", rateLimitNumber, i)
	return true
}

type RateLimitNumber struct {
	second int
	count  int
}

// 根据路由名称限制速率
var apiRateLimitMap = map[string]RateLimitNumber{
	"type:post uri:/user/qr_mobile_pre_login":     {second: 5, count: 200},
	"type:post uri:/user/qr_mobile_confirm_login": {second: 5, count: 200},
	"type:post uri:/user/qr_mobile_cancel_login":  {second: 5, count: 200},
	"type:post uri:/user/logout":                  {second: 5, count: 200},
	"type:post uri:/user/change_pwd":              {second: 5, count: 200},
	"type:post uri:/user/start_bind_email":        {second: 5, count: 200},
	"type:post uri:/user/complete_bind_email":     {second: 5, count: 200},
	"type:post uri:/user/start_change_email":      {second: 5, count: 200},
	"type:post uri:/user/verify_new_email":        {second: 5, count: 200},
	"type:post uri:/user/complete_change_email":   {second: 5, count: 200},
	"type:post uri:/user/start_bind_phone":        {second: 5, count: 200},
	"type:post uri:/user/complete_bind_phone":     {second: 5, count: 200},
	"type:post uri:/user/start_change_phone":      {second: 5, count: 200},
	"type:post uri:/user/verify_new_phone":        {second: 5, count: 200},
	"type:post uri:/user/complete_change_phone":   {second: 5, count: 200},
	"type:post uri:/user/get_userinfo_id":         {second: 5, count: 200},
	"type:post uri:/user/get_userinfo_others":     {second: 5, count: 200},
	"type:post uri:/user/update_userinfo":         {second: 5, count: 200},
	"type:get uri:/auth/permission":               {second: 5, count: 200},
	"type:post uri:/auth/role":                    {second: 5, count: 200},
	"type:get uri:/auth/role":                     {second: 5, count: 200},
	"type:post uri:/auth/group":                   {second: 5, count: 200},
	"type:get uri:/auth/group":                    {second: 5, count: 200},
	"type:post uri:/auth/policy":                  {second: 5, count: 200},
	"type:get uri:/auth/policy":                   {second: 5, count: 200},
	"type:put uri:/auth/policy":                   {second: 5, count: 200},
	"type:post uri:/auth/policy_rule":             {second: 5, count: 200},
	"type:put uri:/auth/policy_rule":              {second: 5, count: 200},
	"type:post uri:/auth/permission/policy":       {second: 5, count: 200},
	"type:delete uri:/auth/permission/policy":     {second: 5, count: 200},
	"type:post uri:/file/init_upload":             {second: 5, count: 200},
}
