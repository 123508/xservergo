create database if not exists xservergo;
use xservergo;

create table if not exists file_alias(
    id binary(16) not null comment '别名id',
    file_id   binary(16) not null comment '文件id',
    user_id   binary(16) not null comment '用户id',
    parent_id binary(16) default null comment '父id',
    recovery_id binary(16) default null comment '进入回收站时的父id',
    file_name varchar(200) not null comment '文件名称',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3) on update CURRENT_TIMESTAMP(3) comment '更新时间',

    is_directory tinyint(1) not null default 0 comment '0:文件 1:目录',

    primary key udx_file_user_id(id),
    unique udx_parent_user_file(parent_id,user_id,file_name),
    key idx_created_at(created_at),
    key idx_updated_at(updated_at),
    fulltext ft_idx_content(file_name) with parser ngram
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件别名信息表';