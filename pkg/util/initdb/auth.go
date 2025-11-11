package initdb

func InitAuthDb() {
	insertPerm("deploy/csv/auth/permission.csv")
	initRolePerm("deploy/csv/auth/role_perm.csv")
	initPolicy("deploy/csv/auth/policy.csv")
	initPolicyRules("deploy/csv/auth/policy_rules.csv")
	initPermissionPolicyRelation("deploy/csv/auth/perm_policy_relation.csv")
}
