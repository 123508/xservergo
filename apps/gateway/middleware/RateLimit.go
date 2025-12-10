package middleware

import (
	"context"
	"fmt"
	"net/http"
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
		// 跳过预检请求，不做限速，直接放行
		if string(c.Request.Method()) == http.MethodOptions {
			c.Next(ctx)
			return
		}
		api := strings.ToLower(fmt.Sprintf("type:%s uri:%s", c.Request.Method(), string(c.URI().Path())))

		ctrl := NewRateLimitCtrl(api)

		if !ctrl.CanAccessAndRateLimit() {
			logs.ErrorLogger.Error("请求被限速,丢弃", zap.String("api", api))
			c.JSON(http.StatusBadRequest, map[string]interface{}{
				"code": 400,
				"msg":  "请求被限速,丢弃",
			})
			c.Abort()
			return
		}

		c.Next(ctx)
	}

}

type RateLimitCtrl struct {
	api string
	ctx context.Context
}

func NewRateLimitCtrl(api string) *RateLimitCtrl {
	return &RateLimitCtrl{api: api, ctx: context.Background()}
}

func (r *RateLimitCtrl) CanAccessAndRateLimit() bool {

	rateLimitNumber := apiRateLimitMap[r.api]

	if !rateLimitNumber.ok {
		return false
	}

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

	key := urds.TakeKey("gateway", "rate-limit", r.api)
	timeKey := urds.TakeKey("gateway", "rate-limit-time", r.api)

	i, _ := db.Rds.Get(r.ctx, key).Int()

	//时间到期,清空限制
	if err := db.Rds.Get(r.ctx, timeKey).Err(); err != nil {
		i = 1
		db.Rds.Set(r.ctx, key, i, time.Duration(rateLimitNumber.second)*time.Second)
		db.Rds.Set(r.ctx, timeKey, true, time.Duration(rateLimitNumber.second)*time.Second)
		return true
	}

	//时间未到期并且超出次数,不允许过
	if i >= rateLimitNumber.count {
		return false
	}

	//时间未到期且未超出数据,允许过
	if err := db.Rds.Get(r.ctx, timeKey).Err(); err == nil {
		i += 1
	} else {
		i = 1
		db.Rds.Set(r.ctx, timeKey, true, time.Duration(rateLimitNumber.second)*time.Second)
	}
	db.Rds.Set(r.ctx, key, i, time.Duration(rateLimitNumber.second)*time.Second)

	return true
}

type RateLimitNumber struct {
	second int
	count  int
	ok     bool
}

// 根据路由名称限制速率
var apiRateLimitMap = map[string]RateLimitNumber{
	"type:post uri:/user/register":                {second: 5, count: 200, ok: true},
	"type:post uri:/user/email_login":             {second: 5, count: 200, ok: true},
	"type:post uri:/user/phone_login":             {second: 5, count: 200, ok: true},
	"type:post uri:/user/account_login":           {second: 5, count: 200, ok: true},
	"type:post uri:/user/sms_login":               {second: 5, count: 200, ok: true},
	"type:post uri:/user/generate_qrCode":         {second: 5, count: 200, ok: true},
	"type:post uri:/user/qr_pre_login":            {second: 5, count: 200, ok: true},
	"type:post uri:/user/qr_login":                {second: 5, count: 200, ok: true},
	"type:post uri:/user/forget_pwd":              {second: 5, count: 200, ok: true},
	"type:post uri:/user/reset_pwd":               {second: 5, count: 200, ok: true},
	"type:post uri:/user/qr_mobile_pre_login":     {second: 5, count: 200, ok: true},
	"type:post uri:/user/qr_mobile_confirm_login": {second: 5, count: 200, ok: true},
	"type:post uri:/user/qr_mobile_cancel_login":  {second: 5, count: 200, ok: true},
	"type:post uri:/user/logout":                  {second: 5, count: 200, ok: true},
	"type:post uri:/user/change_pwd":              {second: 5, count: 200, ok: true},
	"type:post uri:/user/start_bind_email":        {second: 5, count: 200, ok: true},
	"type:post uri:/user/complete_bind_email":     {second: 5, count: 200, ok: true},
	"type:post uri:/user/start_change_email":      {second: 5, count: 200, ok: true},
	"type:post uri:/user/verify_new_email":        {second: 5, count: 200, ok: true},
	"type:post uri:/user/complete_change_email":   {second: 5, count: 200, ok: true},
	"type:post uri:/user/start_bind_phone":        {second: 5, count: 200, ok: true},
	"type:post uri:/user/complete_bind_phone":     {second: 5, count: 200, ok: true},
	"type:post uri:/user/start_change_phone":      {second: 5, count: 200, ok: true},
	"type:post uri:/user/verify_new_phone":        {second: 5, count: 200, ok: true},
	"type:post uri:/user/complete_change_phone":   {second: 5, count: 200, ok: true},
	"type:post uri:/user/get_userinfo_id":         {second: 5, count: 200, ok: true},
	"type:post uri:/user/get_userinfo_others":     {second: 5, count: 200, ok: true},
	"type:post uri:/user/update_userinfo":         {second: 5, count: 200, ok: true},
	"type:get uri:/auth/permission":               {second: 5, count: 200, ok: true},
	"type:post uri:/auth/role":                    {second: 5, count: 200, ok: true},
	"type:get uri:/auth/role":                     {second: 5, count: 200, ok: true},
	"type:post uri:/auth/group":                   {second: 5, count: 200, ok: true},
	"type:get uri:/auth/group":                    {second: 5, count: 200, ok: true},
	"type:post uri:/auth/policy":                  {second: 5, count: 200, ok: true},
	"type:get uri:/auth/policy":                   {second: 5, count: 200, ok: true},
	"type:put uri:/auth/policy":                   {second: 5, count: 200, ok: true},
	"type:post uri:/auth/policy_rule":             {second: 5, count: 200, ok: true},
	"type:put uri:/auth/policy_rule":              {second: 5, count: 200, ok: true},
	"type:post uri:/auth/permission/policy":       {second: 5, count: 200, ok: true},
	"type:delete uri:/auth/permission/policy":     {second: 5, count: 200, ok: true},
	"type:post uri:/file/init_upload":             {second: 5, count: 200, ok: true},
	"type:post uri:/file/upload_chunk":            {second: 5, count: 200, ok: true},
	"type:post uri:/file/upload_verify":           {second: 5, count: 200, ok: true},
	"type:post uri:/file/direct_upload":           {second: 5, count: 200, ok: true},
	"type:post uri:/file/download":                {second: 5, count: 1000, ok: true},
	"type:post uri:/file/pre_download":            {second: 5, count: 500, ok: true},
}
