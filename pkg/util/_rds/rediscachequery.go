package _rds

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/util/component/pub"
	"go.uber.org/zap"

	"github.com/redis/go-redis/v9"
	"math/rand"
	"time"
)

type ListCacheComponent[Id pub.IntegerNumber, Item pub.ItemType[Id]] struct {
	Rds             *redis.Client                       //redis客户端
	Ctx             context.Context                     //上下文传递,之后要做链路追踪
	ListKey         string                              //查询数据唯一标识数组所需要的键
	DetailKeyPrefix string                              //查询详细数据所需要的键前一部分,最后拼接的结果是 DetailKeyPrefix:id
	Marshal         func(v any) ([]byte, error)         //序列化方法,需要自己实现
	Unmarshal       func(data []byte, target any) error //反序列化方法,需要自己实现
	FullQueryExec   func() ([]Item, error)              //全量查询,查询所有数据
	PartQueryExec   func(fails []Id) ([]Item, error)    //部分查询,查询缓存失效的数据
	Expires         time.Duration                       //过期时间
	Random          time.Duration                       //随机过期时间
	MaxLostRate     int                                 //最大缓存失效比率,超过整个数就会重查,0~100
	Sort            func([]Item) []Item                 //给查询结果进行排序(这里是给已经查完的)
	UniqueSig       string                              //指定数据的唯一标识
}

// 参数校验部分
func (c *ListCacheComponent[Id, Item]) checkAndRepair() error {

	//不允许过期时间小于等于0
	if c.Expires <= 0 {
		c.Expires = time.Duration(5) * time.Minute
	}

	if c.Random <= 0 {
		c.Random = time.Duration(rand.Intn(3)) * time.Hour
	}

	if c.ListKey == "" {
		return errors.New("ListKey is required")
	}

	if c.DetailKeyPrefix == "" {
		return errors.New("DetailKeyPrefix is required")
	}

	if c.MaxLostRate > 100 {
		c.MaxLostRate = 30
	}

	if c.Rds == nil {
		return errors.New("_rds is nil")
	}

	if c.Ctx == nil {
		c.Ctx = context.Background()
	}

	if c.UniqueSig == "" {
		c.UniqueSig = "id"
	}

	if c.Marshal == nil {
		c.Marshal = json.Marshal
	}

	if c.Unmarshal == nil {
		c.Unmarshal = json.Unmarshal
	}

	if c.FullQueryExec == nil {
		return errors.New("fullQueryExec is nil")
	}

	if c.Sort == nil {
		c.Sort = func(items []Item) []Item {
			return items
		}
	}

	return nil
}

//id列表+分级详情缓存

//id列表指的是在查询指定范围的时候从redis中查询是否存在其对应的List集合,然后再从详情缓存中查询并组装返回数组
//全量查询是指直接从数据库中去查所有请求的内容(直接打入数据库)
//部分查询是当某几条缓存失效的时候会去数据库中找并补充
//有可能存在幽灵数据的问题,所以在删除数据的时候要直接模糊匹配清理对List集合查询对应的key

func (c *ListCacheComponent[Id, Item]) QueryListWithCache() ([]Item, error) {

	err := c.checkAndRepair()

	if err != nil {
		return nil, err
	}

	res := make([]Item, 0)

	key := c.ListKey

	marshalData, err := c.Rds.Get(c.Ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		logs.ErrorLogger.Error("读取ID列表缓存失败", zap.Error(err))
		// 可选择直接回源
	}

	list := make([]Id, 0)
	fail := make([]Id, 0)
	itemMap := make(map[Id]Item)

	ok := c.Unmarshal([]byte(marshalData), &list)

	//按照list查询详情缓存
	for _, id := range list {
		var t Item
		key := TakeKey(c.DetailKeyPrefix, id)
		marshal, err := c.Rds.Get(c.Ctx, key).Result()
		if err != nil || c.Unmarshal([]byte(marshal), &t) != nil {
			fail = append(fail, id)
			continue
		}
		itemMap[id] = t
	}

	//计算缓存失效比率
	rate := 100

	if len(list) != 0 {
		rate = len(fail) * 100 / len(list)
	}

	if ok != nil || rate > c.MaxLostRate {
		// 执行查询并处理错误
		result, err := c.FullQueryExec()

		if err != nil || result == nil {
			return nil, err
		} else {
			res = result
		}

		//构建ID数组
		idList := make([]Id, 0, len(res))
		for _, v := range res {
			idList = append(idList, v.GetID())
		}

		//序列化并存储ID列表缓存
		marshal, err := c.Marshal(idList)

		if err != nil {
			logs.ErrorLogger.Error("序列化数组错误", zap.Error(err))
		} else {
			// 设置过期时间
			if setErr := c.Rds.Set(c.Ctx, key, marshal, c.Expires+c.Random).Err(); setErr != nil {
				logs.ErrorLogger.Error("缓存失败", zap.Error(setErr))
			}
		}

		//详情内容分级存储
		for _, v := range res {
			key := TakeKey(c.DetailKeyPrefix, v.GetID())
			jsonData, err := c.Marshal(v)
			if err != nil || jsonData == nil {
				logs.ErrorLogger.Error("序列化错误", zap.Error(err))
			} else {
				if err = c.Rds.Set(c.Ctx, key, jsonData, c.Expires+time.Duration(rand.Intn(10))*time.Minute).Err(); err != nil {
					logs.ErrorLogger.Error("缓存失败", zap.Error(err))
				}
			}
		}

	} else {

		//缓存失效比例较低,逐条查询并放入缓存
		if len(fail) > 0 {
			var missedItem []Item

			if result, err := c.PartQueryExec(fail); err != nil {
				return nil, err
			} else {
				missedItem = result
			}

			for _, item := range missedItem {
				itemMap[item.GetID()] = item
				//放入缓存
				key := TakeKey(c.DetailKeyPrefix, item.GetID())
				jsonData, err := c.Marshal(item)
				if err != nil || jsonData == nil {
					logs.ErrorLogger.Error("序列化错误", zap.Error(err))
				} else {
					if err = c.Rds.Set(c.Ctx, key, jsonData, c.Expires+c.Random).Err(); err != nil {
						logs.ErrorLogger.Error("缓存失败", zap.Error(err))
					}
				}
			}
		}

		res = make([]Item, 0)

		for _, v := range list {
			if v, ok := itemMap[v]; ok {
				res = append(res, v)
			}
		}

		logs.AccessLogger.Info("查询缓存成功")
	}

	return c.Sort(res), nil
}

type SimpleCacheComponent[Id pub.IntegerNumber, E any] struct {
	Rds       *redis.Client                       //redis客户端
	Ctx       context.Context                     //上下文传递,之后要做链路追踪
	Key       string                              //存储的键
	Marshal   func(v any) ([]byte, error)         //序列化方法,需要自己实现
	Unmarshal func(data []byte, target any) error //反序列化方法,需要自己实现
	QueryExec func() (E, error)                   //正常查询所有数据的操作
	Expires   time.Duration                       //过期时间
	Random    time.Duration                       //随机过期时间
}

func (c *SimpleCacheComponent[Id, E]) checkAndRepair() error {
	if c.Expires <= 0 {
		c.Expires = time.Duration(3) * time.Minute
	}
	if c.Random <= 0 {
		c.Random = time.Duration(rand.Intn(3)) * time.Hour
	}
	if c.Marshal == nil {
		c.Marshal = json.Marshal
	}
	if c.Unmarshal == nil {
		c.Unmarshal = json.Unmarshal
	}

	if c.QueryExec == nil {
		return errors.New("queryExec is nil")
	}

	if c.Key == "" {
		return errors.New("key is empty")
	}
	return nil
}

//简单查询,就是查完后放入缓存,之后能从缓存中查数据,查询数据库失败返回空数

func (c *SimpleCacheComponent[Id, E]) QueryWithCache() (E, error) {

	var items E

	err := c.checkAndRepair()

	if err != nil {
		return items, err
	}

	result, err := c.Rds.Get(c.Ctx, c.Key).Result()

	//查询缓存失败
	if err != nil || c.Unmarshal([]byte(result), &items) != nil {

		exec, err := c.QueryExec()

		if err != nil {
			return items, err
		} else {
			items = exec
		}

		//序列化数据
		marshal, err := c.Marshal(items)

		if err != nil {
			logs.ErrorLogger.Error("序列化数据失败", zap.Error(err))
		} else {
			//把数据放入缓存
			if setErr := c.Rds.Set(c.Ctx, c.Key, marshal, c.Expires+c.Random).Err(); setErr != nil {
				logs.ErrorLogger.Error("缓存数据失败", zap.Error(setErr))
			}
		}

	} else {
		logs.AccessLogger.Info("查询缓存成功")
	}

	return items, nil
}
