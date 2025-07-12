package condition

import (
	"fmt"
	"testing"
)

func TestBuildCondition(t *testing.T) {

	//使用构建器构建查询条件,适合快速高效构建(无法识别如between ... and ...的复杂条件)
	t.Run("TestBuilder", func(t *testing.T) {
		build := NewConditionBuilder().
			And("id", "=", "1").
			Or("name", "in", "('liy','ta')").
			Build()

		fmt.Println(build.ToSQL())
	})

	//使用结构体构建查询条件,适合组装复杂条件
	t.Run("TestStruct", func(t *testing.T) {
		c := ConditionBuilder{
			cond: And{
				[]Condition{
					Or{
						[]Condition{
							Expr{
								Field:    "name",
								Operator: "in",
								Value:    "('zhang','li','fu')",
							},
							Expr{
								Field:    "id",
								Operator: "is null",
								Value:    nil,
							},
						},
					},
					Expr{
						Field:    "id",
						Operator: "between",
						Value:    []int{12, 200},
					},
				},
			},
		}

		fmt.Println(c.Build().ToSQL())
	})
}
