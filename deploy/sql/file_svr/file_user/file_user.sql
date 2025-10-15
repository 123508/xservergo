create database if not exists xservergo;
use xservergo;

create table if not exists file_user(
     id      binary(16) not null comment '唯一索引',
     file_id binary(16) not null comment '关联文件id',
     user_id binary(16) not null comment '用户id',
     file_alias varchar(255) not null default '新建文件夹' comment '用户自定义的文件名',

     created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
     deleted_at datetime default null comment '进入回收站时间',

     primary key idx_user_file_id(user_id,file_id),
     key idx_file_id(file_id),
     unique index idx_id(id)
)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件用户表';