create database if not exists xservergo;
use xservergo;

-- 权限覆盖标记与路径摘要缓存方案

create  table if not exists file_tree(
  ancestor binary(16) not null comment '祖先节点ID',
  descendant binary(16) not null comment '后代节点ID',
  depth int not null comment'层级深度(0-自身)',
  primary key (ancestor, descendant),
  index idx_descendant_depth (descendant, depth)
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_0900_ai_ci
    COMMENT='文件树表';