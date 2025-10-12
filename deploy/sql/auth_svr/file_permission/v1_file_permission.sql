create database if not exists xservergo;
use xservergo;

-- 文件具体权限表
create table if not exists file_permission(

    id binary(16) not null comment '文件具体权限唯一标识',

    -- 后续权限定义请用1<<n位来标识,是否有权限基于与运算,增加权限使用或运算,撤销权限使用异或运算
    permission_type int unsigned default 1 comment '文件具体权限类型列表存储:1:读 2预览 4下载 8修改 16新建 32删除',

    primary key (id) comment '主键'

)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件具体权限表';