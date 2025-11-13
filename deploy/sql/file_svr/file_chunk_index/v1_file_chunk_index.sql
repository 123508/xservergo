create database if not exists xservergo;
use xservergo;

create table if not exists file_chunk_index(
   file_id binary(16) not null comment '文件id',
   chunk_id binary(16) not null comment '文件分片id',
   chunk_index int unsigned not null  comment '分片序号',

   created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
   updated_at datetime(3) not null default current_timestamp(3) on update CURRENT_TIMESTAMP(3) comment '更新时间',

   primary key idx_file_chunk(file_id,chunk_id),
   key idx(file_id)
)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件分片索引表';