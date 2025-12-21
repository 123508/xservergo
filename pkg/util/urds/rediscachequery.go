package urds

import (
	"context"
	"encoding/json"
	"errors"

	db "github.com/123508/xservergo/pkg/database"
	"github.com/123508/xservergo/pkg/logs"
	"github.com/123508/xservergo/pkg/util/component/pub"
	"go.uber.org/zap"

	"math/rand"
	"time"

	"github.com/redis/go-redis/v9"
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
}

func NewListCacheComponent[Id pub.IntegerNumber, Item pub.ItemType[Id]](
	rds *redis.Client,
	ctx context.Context,
	listKey string,
	detailKeyPrefix string,
	marshal func(v any) ([]byte, error),
	unmarshal func(data []byte, target any) error,
	fullQueryExec func() ([]Item, error),
	partQueryExec func(fails []Id) ([]Item, error),
	expires time.Duration,
	random time.Duration,
	maxLostRate int,
	Sort func([]Item) []Item,
) *ListCacheComponent[Id, Item] {
	return &ListCacheComponent[Id, Item]{
		Rds:             rds,
		Ctx:             ctx,
		ListKey:         listKey,
		DetailKeyPrefix: detailKeyPrefix,
		Marshal:         marshal,
		Unmarshal:       unmarshal,
		FullQueryExec:   fullQueryExec,
		PartQueryExec:   partQueryExec,
		Expires:         expires,
		Random:          random,
		MaxLostRate:     maxLostRate,
		Sort:            Sort,
	}
}

func NewListCacheComponentWithDefault[Id pub.IntegerNumber, Item pub.ItemType[Id]](
	listKey string,
	detailKeyPrefix string,
	fullQueryExec func() ([]Item, error),
	partQueryExec func(fails []Id) ([]Item, error),
) *ListCacheComponent[Id, Item] {
	return &ListCacheComponent[Id, Item]{
		Rds:             db.Rds,
		Ctx:             context.Background(),
		ListKey:         listKey,
		DetailKeyPrefix: detailKeyPrefix,
		Marshal:         json.Marshal,
		Unmarshal:       json.Unmarshal,
		FullQueryExec:   fullQueryExec,
		PartQueryExec:   partQueryExec,
		Expires:         10 * time.Minute,
		Random:          2 * time.Minute,
		MaxLostRate:     30,
		Sort: func(items []Item) []Item {
			return items
		},
	}
}

func (c *ListCacheComponent[Id, Item]) SetRedisClient(rds *redis.Client) *ListCacheComponent[Id, Item] {
	c.Rds = rds
	return c
}

func (c *ListCacheComponent[Id, Item]) SetContext(ctx context.Context) *ListCacheComponent[Id, Item] {
	c.Ctx = ctx
	return c
}

func (c *ListCacheComponent[Id, Item]) SetListKey(listKey string) *ListCacheComponent[Id, Item] {
	c.ListKey = listKey
	return c
}

func (c *ListCacheComponent[Id, Item]) SetDetailKey(detailKeyPrefix string) *ListCacheComponent[Id, Item] {
	c.DetailKeyPrefix = detailKeyPrefix
	return c
}

// SetMarshalAndUnMarshal 设置序列化和反序列化方法
func (c *ListCacheComponent[Id, Item]) SetMarshalAndUnMarshal(
	marshal func(v any) ([]byte, error),
	unmarshal func(data []byte, target any) error) *ListCacheComponent[Id, Item] {
	c.Marshal = marshal
	c.Unmarshal = unmarshal
	return c
}

func (c *ListCacheComponent[Id, Item]) SetFullQueryExec(fullQueryExec func() ([]Item, error)) *ListCacheComponent[Id, Item] {
	c.FullQueryExec = fullQueryExec
	return c
}

func (c *ListCacheComponent[Id, Item]) SetPartQueryExec(partQueryExec func(fails []Id) ([]Item, error)) *ListCacheComponent[Id, Item] {
	c.PartQueryExec = partQueryExec
	return c
}

func (c *ListCacheComponent[Id, Item]) SetExpires(expires time.Duration) *ListCacheComponent[Id, Item] {
	c.Expires = expires
	return c
}

func (c *ListCacheComponent[Id, Item]) SetRandom(random time.Duration) *ListCacheComponent[Id, Item] {
	c.Random = random
	return c
}

func (c *ListCacheComponent[Id, Item]) SetMaxLostRate(maxLostRate int) *ListCacheComponent[Id, Item] {
	c.MaxLostRate = maxLostRate
	return c
}

func (c *ListCacheComponent[Id, Item]) SetSort(sort func(items []Item) []Item) *ListCacheComponent[Id, Item] {
	c.Sort = sort
	return c
}

// 参数校验部分
func (c *ListCacheComponent[Id, Item]) checkAndRepair() error {

	//不允许过期时间小于等于0
	if c.Expires <= 0 {
		c.Expires = time.Duration(10) * time.Minute
	}

	if c.Random <= 0 {
		c.Random = time.Duration(rand.Intn(3)) * time.Minute
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
		return errors.New("urds is nil")
	}

	if c.Ctx == nil {
		c.Ctx = context.Background()
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

	//参数校验
	err := c.checkAndRepair()
	if err != nil {
		return nil, err
	}

	key := c.ListKey

	//redis中取出缓存数据
	marshalData, err := c.Rds.Get(c.Ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		logs.ErrorLogger.Error("读取ID列表缓存失败", zap.Error(err))
		// 可选择直接回源
	}

	list := make([]Id, 0)
	fail := make([]Id, 0)
	itemMap := make(map[Id]Item)

	//反序列化查询id列表
	ok := c.Unmarshal([]byte(marshalData), &list)

	//查询具体数据缓存并填充到map中
	fail, itemMap = c.addItemToMap(list, fail, itemMap)

	//计算缓存失效比率
	rate := 100

	if len(list) != 0 {
		rate = len(fail) * 100 / len(list)
	}

	//反序列化数据失败或者缓存失效比例过高就走全量查询,否则就走分量查询
	if ok != nil || rate > c.MaxLostRate {
		result, ansErr := c.fullQueryExec()

		c.fullQueryExecAddCache(key, result)

		return result, ansErr
	} else {
		return c.partQueryExec(fail, list, itemMap)
	}
}

// 向itemMap中填充数据,使用successMap接受
func (c *ListCacheComponent[Id, Item]) addItemToMap(list, fail []Id, itemMap map[Id]Item) (failure []Id, successMap map[Id]Item) {

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

	return failure, itemMap
}

// 全量查询
func (c *ListCacheComponent[Id, Item]) fullQueryExec() (ans []Item, err error) {

	// 执行查询并处理错误
	result, err := c.FullQueryExec()

	//查询有问题,直接返回
	if err != nil || result == nil {
		return nil, err
	}

	//返回排序后的数组
	return c.Sort(result), nil
}

// 全量查询添加缓存部分
func (c *ListCacheComponent[Id, Item]) fullQueryExecAddCache(key string, result []Item) {

	//构建ID数组
	idList := make([]Id, 0)
	for _, v := range result {
		idList = append(idList, v.GetID())
	}

	//序列化并存储ID列表缓存
	marshal, err := c.Marshal(idList)
	if err != nil {
		logs.ErrorLogger.Error("序列化数组错误", zap.Error(err))
	} else {
		// 设置过期时间
		setErr := c.Rds.Set(c.Ctx, key, marshal, c.Expires+c.Random).Err()
		if setErr != nil {
			logs.ErrorLogger.Error("缓存失败", zap.Error(setErr))
		}
	}

	//详情内容分级存储
	for _, v := range result {
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
}

// 分量查询(强制写入缓存)
func (c *ListCacheComponent[Id, Item]) partQueryExec(fail, list []Id, itemMap map[Id]Item) ([]Item, error) {
	res := make([]Item, 0)

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
			//序列化数据并放入缓存,失败就报错,否则返回
			jsonData, err := c.Marshal(item)
			if err != nil || jsonData == nil {
				logs.ErrorLogger.Error("序列化错误", zap.Error(err))
			} else {
				key := TakeKey(c.DetailKeyPrefix, item.GetID())
				if err = c.Rds.Set(c.Ctx, key, jsonData, c.Expires+c.Random).Err(); err != nil {
					logs.ErrorLogger.Error("缓存失败", zap.Error(err))
				}
			}
		}
	}

	res = make([]Item, 0)

	for _, v := range list {
		if val, ok := itemMap[v]; ok {
			res = append(res, val)
		}
	}

	logs.AccessLogger.Info("查询缓存成功")

	return c.Sort(res), nil
}

type SimpleCacheComponent[E any] struct {
	Rds       *redis.Client                       //redis客户端
	Ctx       context.Context                     //上下文传递,之后要做链路追踪
	Key       string                              //存储的键
	Marshal   func(v any) ([]byte, error)         //序列化方法,需要自己实现
	Unmarshal func(data []byte, target any) error //反序列化方法,需要自己实现
	QueryExec func() (E, error)                   //正常查询所有数据的操作
	Expires   time.Duration                       //过期时间
	Random    time.Duration                       //随机过期时间
}

func NewSimpleCacheComponent[E any](
	rds *redis.Client,
	ctx context.Context,
	key string,
	marshal func(v any) ([]byte, error),
	unmarshal func(data []byte, target any) error,
	queryExec func() (E, error),
	expires time.Duration,
	random time.Duration,
) *SimpleCacheComponent[E] {
	return &SimpleCacheComponent[E]{
		Rds:       rds,
		Ctx:       ctx,
		Key:       key,
		Marshal:   marshal,
		Unmarshal: unmarshal,
		QueryExec: queryExec,
		Expires:   expires,
		Random:    random,
	}
}

func NewSimpleCacheComponentWithDefault[E any](
	key string,
	QueryExec func() (E, error),
) *SimpleCacheComponent[E] {
	return &SimpleCacheComponent[E]{
		Rds:       db.Rds,
		Ctx:       context.Background(),
		Key:       key,
		Marshal:   json.Marshal,
		Unmarshal: json.Unmarshal,
		QueryExec: QueryExec,
		Expires:   10 * time.Minute,
		Random:    2 * time.Minute,
	}
}

func (c *SimpleCacheComponent[E]) SetRedisClient(rds *redis.Client) *SimpleCacheComponent[E] {
	c.Rds = rds
	return c
}

func (c *SimpleCacheComponent[E]) SetContext(ctx context.Context) *SimpleCacheComponent[E] {
	c.Ctx = ctx
	return c
}

func (c *SimpleCacheComponent[E]) SetKeyName(key string) *SimpleCacheComponent[E] {
	c.Key = key
	return c
}

func (c *SimpleCacheComponent[E]) SetMarshalAndUnmarshal(
	marshal func(v any) ([]byte, error),
	unmarshal func(data []byte, target any) error,
) *SimpleCacheComponent[E] {
	c.Marshal = marshal
	c.Unmarshal = unmarshal
	return c
}

func (c *SimpleCacheComponent[E]) SetQueryExec(queryExec func() (E, error)) *SimpleCacheComponent[E] {
	c.QueryExec = queryExec
	return c
}

func (c *SimpleCacheComponent[E]) SetExpires(expires time.Duration) *SimpleCacheComponent[E] {
	c.Expires = expires
	return c
}

func (c *SimpleCacheComponent[E]) SetRandom(random time.Duration) *SimpleCacheComponent[E] {
	c.Random = random
	return c
}

func (c *SimpleCacheComponent[E]) checkAndRepair() error {
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

func (c *SimpleCacheComponent[E]) QueryWithCache() (E, error) {

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

		//序列化数据并写入缓存
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
