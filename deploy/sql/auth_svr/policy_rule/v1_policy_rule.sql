create database if not exists xservergo;
use xservergo;

-- 策略规则表
create table if not exists policy_rule (
    id  binary(16) not null  comment '策略规则id',
    policy_code varchar(100) not null  comment '策略唯一标识符',
    attribute_type enum(
        'String',  -- 字符串类型
        'Int',     -- 整型类型
        'Int8',    -- 8位整型
        'Int16',   -- 16位整型
        'Int32',   -- 32位整型
        'Int64',   -- 64位整型
        'Uint',    -- 无符号整型
        'Uint8',   -- 8位无符号整型
        'Uint16',  -- 16位无符号整型
        'Uint32',  -- 32位无符号整型
        'Uint64',  -- 64位无符号整型
        'Float32', -- 32位浮点数
        'Float64', -- 64位浮点数
        'Boolean', -- 布尔类型
        'Date',    -- 日期类型
        'List'     -- 列表类型
    ) not null default 'String' comment '属性类型',
    attribute_key varchar(100) not null comment '属性键',
    attribute_value varchar(100) not null comment '属性值',
    operator enum(
        '=',           -- 等于
        '!=',          -- 不等于
        '>',           -- 大于
        '<',           -- 小于
        '>=',          -- 大于等于
        '<=',          -- 小于等于
        'Contains',    -- 包含
        'StartsWith',  -- 以...开始
        'EndsWith',     -- 以...结束
        'Regex',       -- 正则表达式匹配
        'In'           -- 在列表中
    ) not null default '=' comment '操作符',
    status tinyint(1) not null default 1 comment '规则是否启用:0不启用 1启用',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3)  on update CURRENT_TIMESTAMP(3) comment '更新时间',

    -- 删除三元组
    deleted_at datetime(3) default null comment '删除时间(软删除)',
    is_deleted tinyint(1) generated always as (IF(deleted_at is null, 0, 1)) virtual ,
    deleted_date date generated always as (COALESCE(DATE(deleted_at), '9999-12-31')) virtual ,

    -- 唯一约束的虚拟列
    deleted_at_fixed datetime(3) generated always as (COALESCE(deleted_at, '1970-01-01 00:00:00.000')) virtual,

    -- 审计字段
    version  int not null default 0 comment '版本号',
    created_by binary(16) null comment '创建人id',   -- 允许null
    updated_by binary(16) null comment '修改人id',   -- 允许null

    primary key (id) comment '主键',


    index policy_rule_idx_code_deleted_status(policy_code,is_deleted,status)


)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='策略规则表';