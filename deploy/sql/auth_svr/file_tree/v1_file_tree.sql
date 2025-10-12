create database if not exists xservergo;
use xservergo;

-- 文件树权限表
create table if not exists file_tree(

    file_id binary(16) not null comment '文件树节点唯一标识',
    file_parent_id binary(16) default null comment '文件父节点权限唯一标识',
    file_permission_id binary(16) default  null comment  '文件节点所指向的权限标识: null向上查找父节点的权限,否则直接连查',

    -- 时间戳
    created_at datetime(3) not null default current_timestamp(3) comment '创建时间',
    updated_at datetime(3) not null default current_timestamp(3)  on update CURRENT_TIMESTAMP(3) comment '更新时间',

    created_by binary(16) null comment '创建人id',   -- 允许null
    updated_by binary(16) null comment '修改人id',   -- 允许null

    -- 联合索引方便查询
    index idx_file_permission_parent_id(file_id,file_permission_id,file_parent_id),
    index idx_file_permission(file_permission_id)

)engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件树权限表';