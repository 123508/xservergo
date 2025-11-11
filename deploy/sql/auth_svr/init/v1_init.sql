# 初始化角色

set @SYSTEM_USER_ID = UUID_TO_BIN('00000000-0000-7000-8000-000000000000');

# 访客

insert into roles (id, code, name, description, status, created_at, version, created_by) values
(
    UUID_TO_BIN(UUID()),
    'visitor',
    '访客',
    '访客角色，拥有最少的权限',
    1,
    NOW(3),
    1,
    @SYSTEM_USER_ID
);

# 用户

insert into roles (id, code, name, description, status, created_at, version, created_by) values
(
    UUID_TO_BIN(UUID()),
    'user',
    '用户',
    '普通用户角色，拥有基本的权限',
    1,
    NOW(3),
    1,
    @SYSTEM_USER_ID
);

# 管理员

insert into roles (id, code, name, description, status, created_at, version, created_by) values
(
    UUID_TO_BIN(UUID()),
    'admin',
    '管理员',
    '管理员角色，拥有大部分权限',
    1,
    NOW(3),
    1,
    @SYSTEM_USER_ID
);

# 超级管理员

insert into roles (id, code, name, description, status, created_at, version, created_by) values
(
    UUID_TO_BIN(UUID()),
    'super_admin',
    '超级管理员',
    '超级管理员角色，拥有所有权限',
    1,
    NOW(3),
    1,
    @SYSTEM_USER_ID
);