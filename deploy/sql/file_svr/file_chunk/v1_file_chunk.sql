create database if not exists xservergo;
use xservergo;

create table if not exists file_chunk(
    id binary(16) not null comment '唯一标识id',
    chunk_hash varchar(100) not null comment '分片内容hash',
    chunk_name varchar(255) not null comment '分片名称',

    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3) on update CURRENT_TIMESTAMP(3) comment '更新时间',

    primary key idx_id(id),
    unique key idx_path(chunk_hash)
)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件分片表';