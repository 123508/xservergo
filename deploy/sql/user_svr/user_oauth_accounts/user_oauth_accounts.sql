create database if not exists xservergo;
use xservergo;

-- 用户第三方账号表
create table if not exists user_oauth_accounts(
    id  binary(16) not null comment '记录id',
    user_id binary(16) not null comment '用户id',
    provider_uid varchar(100) default null comment '第三方用户ID(openid/sub/id)[低优先级]',
    provider_unionid varchar(100) default null comment '第三方跨应用ID[高优先级]',
    provider  varchar(100) default null comment '第三方服务提供方',
    refresh_token varchar(200) default null comment '第三方refresh_token',
    refresh_token_expire_at datetime(3) default null comment 'refresh_token过期时间',

    provider_nickname varchar(100) default null comment '第三方昵称',
    provider_avatar varchar(255) default null comment '头像',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3) on update current_timestamp(3) comment '更新时间',

    -- 删除三元组
    deleted_at datetime(3) default null comment '删除时间(软删除)',
    deleted_date date generated always as (COALESCE(DATE(deleted_at), '9999-12-31')) virtual ,

    -- 唯一约束的虚拟列
    deleted_at_fixed datetime(3) generated always as (COALESCE(deleted_at, '1970-01-01 00:00:00.000')) virtual,

    created_by binary(16) null comment '创建人id',   -- 允许null
    updated_by binary(16) null comment '修改人id',   -- 允许null

    primary key (id),
    unique key udx_provider_uid(provider, provider_uid,deleted_at_fixed),
    unique key udx_provider_unionid(provider, provider_unionid, deleted_at_fixed),

    key idx_user_id(user_id, deleted_at)

)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='用户第三方账号表';