package initdb

func InitUserDb() {
	insertPerm("deploy/csv/user/permission.csv")
	initRolePerm("deploy/csv/user/role_perm.csv")
	initPolicy("deploy/csv/user/policy.csv")
	initPolicyRules("deploy/csv/user/policy_rules.csv")
	initPermissionPolicyRelation("deploy/csv/user/perm_policy_relation.csv")
}
