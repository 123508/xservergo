package sort

import (
	"fmt"
	"testing"
)

func TestSort(t *testing.T) {

	//翻转排序条件
	t.Run("BuildSort", func(t *testing.T) {
		sortItems := NewSortOnMySQL().AddSortItem("test", ASC).AddSortItems([]Sort{
			SortExpr{
				FieldName: "id",
				Order:     ASC,
			},
			RowExpr{
				Expr: "age desc",
			},
		})

		fmt.Println(sortItems.ToSorts(false))
		fmt.Println(sortItems.ToSorts(true))
	})

	//条件去重
	t.Run("DistinctSort", func(t *testing.T) {
		item := NewSortOnMySQL().AddSortItem("id", ASC).
			AddSortItem("time", ASC).
			AddSortItem("id", DESC)
		fmt.Println(item.ToSorts(false))
	})
}
