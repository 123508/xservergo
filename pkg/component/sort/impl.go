package sort

import (
	"fmt"
	"regexp"
	"strings"
)

//对添加排序字段的实现

type SortOrder string

const (
	ASC  SortOrder = "asc"
	DESC SortOrder = "desc"
)

// 仅处理末尾排序关键字（asc/desc），允许结尾有空格，不区分大小写
var orderBySuffixRegexp = regexp.MustCompile(`(?i)\s+(asc|desc)\s*$`)

// SortExpr 元样式
type SortExpr struct {
	FieldName string
	Order     SortOrder
}

func (s SortExpr) ToSortItem() string {

	if s.Order != ASC && s.Order != DESC {
		return fmt.Sprintf("%s %s", s.FieldName, ASC)
	}

	return fmt.Sprintf("%s %s", s.FieldName, s.Order)
}

func (s SortExpr) Reverse() string {
	if s.Order != ASC && s.Order != DESC {
		return fmt.Sprintf("%s %s", s.FieldName, DESC)
	}

	if s.Order == ASC {
		return fmt.Sprintf("%s %s", s.FieldName, DESC)
	}

	return fmt.Sprintf("%s %s", s.FieldName, ASC)
}

func (s SortExpr) GetKey() string {
	return strings.TrimSpace(s.FieldName)
}

type RowExpr struct {
	Expr string
}

func (r RowExpr) checkRight() (bool, string) {

	sp := strings.Split(strings.ToLower(strings.TrimSpace(r.Expr)), " ")

	if len(sp) == 2 &&
		(sp[0] != "asc" && sp[0] != "desc") &&
		(sp[1] == "asc" || sp[1] == "desc") {
		return true, ""
	}

	return false, r.Expr
}

func (r RowExpr) ToSortItem() string {

	if ok, item := r.checkRight(); !ok {
		fmt.Println("输入错误:", item)
		return ""
	}

	return r.Expr
}

func (r RowExpr) Reverse() string {

	if ok, item := r.checkRight(); !ok {
		fmt.Println("输入错误:", item)
		return ""
	}

	// 倒序/升序互换
	return orderBySuffixRegexp.ReplaceAllStringFunc(r.Expr, func(s string) string {
		// s like " desc" or " asc" (可能带空格)
		if strings.Contains(strings.ToLower(s), "asc") {
			return strings.Replace(s, "asc", "desc", 1)
		}
		return strings.Replace(s, "desc", "asc", 1)
	})
}

func (r RowExpr) GetKey() string {
	return strings.TrimSpace(strings.Split(r.Expr, " ")[0])
}

type SortOnMySQL struct {
	Sorts []Sort
}

func NewSortOnMySQL() *SortOnMySQL {
	return &SortOnMySQL{
		Sorts: make([]Sort, 0),
	}
}

func (s *SortOnMySQL) AddSortItems(sorts []Sort) *SortOnMySQL {
	s.Sorts = append(s.Sorts, sorts...)
	return s
}

func (s *SortOnMySQL) AddSortItem(FieldName string, order SortOrder) *SortOnMySQL {
	s.Sorts = append(s.Sorts, SortExpr{FieldName: FieldName, Order: order})
	return s
}

func (s *SortOnMySQL) ToSorts(reverse bool) []string {

	var parts []string

	if s == nil {
		return parts
	}

	if s.Sorts == nil {
		s.Sorts = make([]Sort, 0)
	}

	single := make(map[string]int)

	//这里是正常字段的添加
	for _, v := range s.Sorts {

		var part string

		single[v.GetKey()]++

		if single[v.GetKey()] > 1 {
			continue
		}

		if reverse {
			part = v.Reverse()
		} else {
			part = v.ToSortItem()
		}

		parts = append(parts, part)
	}

	return parts
}
