create database if not exists xservergo;
use xservergo;

create table if not exists file(
    id binary(16) not null comment '文件id',
    user_id binary(16) not null comment '用户id',
    file_md5 varchar(32) comment '文件md5值',
    parent_id binary(16) default null comment '父文件id',
    file_size bigint(20) unsigned not null default 0 comment '文件大小',
    file_name varchar(200) not null comment '文件名称',
    file_cover varchar(100)  comment '封面',
    file_path varchar(100)  comment '文件路径',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3) on update CURRENT_TIMESTAMP(3) comment '更新时间',
    deleted_at datetime default null comment '进入回收站时间',

    is_directory tinyint(1) not null default 0 comment '0:文件 1:目录',
    file_type tinyint(5)  comment '1视频 2音频 3图片 4pdf 5doc 6excel 7txt 8code 9zip 10其他',
    is_public tinyint(1) comment '0不公开 1公开',

    status tinyint(1) default null comment '标记删除: 0删除 1回收站 2正常 3转码中 4转码失败',
    store_type tinyint(1) comment '1本地 2云存储',

    unique key udx_file_user_id(id,user_id),
    key idx_created_at(created_at),
    key idx_user_id(user_id),
    key idx_md5(file_md5),
    key idx_parent_id(parent_id),
    key idx_status(status),
    key idx_recovery_time(deleted_at)
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件信息表';