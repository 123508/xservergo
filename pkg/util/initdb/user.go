package initdb

import (
	"encoding/csv"
	"os"

	database "github.com/123508/xservergo/pkg/database"
)

func InsertUserPerm() {
	// 初始化数据库连接
	db, err := database.InitMySQLDB()
	if err != nil {
		panic(err)
	}

	// 读取csv文件
	file, err := os.Open("deploy/csv/user/permission.csv")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	// 解析csv文件
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	// 插入数据库
	insertPermStmt := `insert into permission (id, code, name, description, resource, method, status, need_policy, created_at, version, created_by)
						values (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?, ?, NOW(3), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'))`
	for i, record := range records {
		if i == 0 {
			// 跳过表头
			continue
		}
		if len(record) != 8 {
			// 每行必须有8列
			continue
		}
		code := record[0]
		name := record[1]
		description := record[2]
		resource := record[3]
		method := record[4]
		status := record[5]
		needPolicy := record[6]
		version := record[7]
		db.Exec(insertPermStmt, code, name, description, resource, method, status, needPolicy, version)
	}
}

func InitUserRolePerm() {
	// 初始化数据库连接
	db, err := database.InitMySQLDB()
	if err != nil {
		panic(err)
	}

	// 读取csv文件
	file, err := os.Open("deploy/csv/user/role_perm.csv")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	// 解析csv文件
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	// 插入数据库
	insertRolePermissionStmt := `insert into role_permission(role_id, permission_id, status, operator_id, created_at, version, created_by)
						values ((select id from roles where code = ?), (select id from permission where code = ?), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'), NOW(3), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'))`
	for i, record := range records {
		if i == 0 {
			// 跳过表头
			continue
		}
		if len(record) != 4 {
			// 每行必须有4列
			continue
		}
		RoleCode := record[0]
		permCode := record[1]
		status := record[2]
		version := record[3]
		db.Exec(insertRolePermissionStmt, RoleCode, permCode, status, version)
	}
}

func InitPolicy() {
	// 初始化数据库连接
	db, err := database.InitMySQLDB()
	if err != nil {
		panic(err)
	}

	// 读取csv文件
	file, err := os.Open("deploy/csv/user/policy.csv")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	// 解析csv文件
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	// 插入数据库
	insertPolicyStmt := `insert into policy (id, code, name, description, status, created_at, version, created_by)
						values (UUID_TO_BIN(UUID()), ?, ?, ?, ?, NOW(3), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'))`
	for i, record := range records {
		if i == 0 {
			// 跳过表头
			continue
		}
		if len(record) != 5 {
			// 每行必须有5列
			continue
		}
		code := record[0]
		name := record[1]
		description := record[2]
		status := record[3]
		version := record[4]
		db.Exec(insertPolicyStmt, code, name, description, status, version)
	}
}

func InitPolicyRules() {
	// 初始化数据库连接
	db, err := database.InitMySQLDB()
	if err != nil {
		panic(err)
	}

	// 读取csv文件
	file, err := os.Open("deploy/csv/user/policy_rules.csv")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	// 解析csv文件
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	// 插入数据库
	insertPolicyRuleStmt := `insert into policy_rule (id, policy_code, attribute_type, attribute_key, attribute_value, operator, status, created_at, version, created_by)
						values (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?, NOW(3), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'))`

	for i, record := range records {
		if i == 0 {
			// 跳过表头
			continue
		}
		if len(record) != 7 {
			// 每行必须有7列
			continue
		}
		policyCode := record[0]
		attributeType := record[1]
		attributeKey := record[2]
		attributeValue := record[3]
		operator := record[4]
		status := record[5]
		version := record[6]
		db.Exec(insertPolicyRuleStmt, policyCode, attributeType, attributeKey, attributeValue, operator, status, version)
	}
}

func InitPermissionPolicyRelation() {
	// 初始化数据库连接
	db, err := database.InitMySQLDB()
	if err != nil {
		panic(err)
	}

	// 读取csv文件
	file, err := os.Open("deploy/csv/user/perm_policy_relation.csv")
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
		}
	}(file)

	// 解析csv文件
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	// 插入数据库
	insertPermPolicyStmt := `insert into permission_policy_relation(permission_code, policy_code, status, created_at, version, created_by)
    						values (?, ?, ?, NOW(3), ?, UUID_TO_BIN('00000000-0000-7000-8000-000000000000'))`

	for i, record := range records {
		if i == 0 {
			// 跳过表头
			continue
		}
		if len(record) != 4 {
			// 每行必须有4列
			continue
		}
		permCode := record[0]
		policyCode := record[1]
		status := record[2]
		version := record[3]
		db.Exec(insertPermPolicyStmt, permCode, policyCode, status, version)
	}
}
