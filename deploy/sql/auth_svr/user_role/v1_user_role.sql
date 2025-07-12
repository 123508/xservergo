create database if not exists xservergo;
use xservergo;

-- 用户-角色表
create table if not exists user_role(
    user_id binary(16) not null comment '用户id',
    role_id binary(16) not null comment '角色id',
    status   tinyint(1) not null default 1 comment '启用状态: 0禁用 1启用',
    operator_id binary(16) null  comment '操作人(null=系统)',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3) on update CURRENT_TIMESTAMP(3) comment '更新时间',

    -- 删除三元组
    deleted_at datetime(3) default null comment '删除时间(软删除)',
    is_deleted tinyint(1) generated always as (IF(deleted_at is null, 0, 1)) virtual ,
    deleted_date date generated always as (COALESCE(DATE(deleted_at), '9999-12-31')) virtual ,

    -- 审计字段
    version  int not null default 0 comment '版本号',
    created_by binary(16) null comment '创建人id',   -- 允许null
    updated_by binary(16) null comment '修改人id',   -- 允许null

    primary key (user_id,role_id),
    index user_role_idx_user_status(user_id,status),
    constraint user_role_chk_status check ( status in (0,1) )
)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
COMMENT='用户-角色表';
