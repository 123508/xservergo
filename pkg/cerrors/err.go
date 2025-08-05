package cerrors

import (
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
)

//----------------- repo层错误 -----------------//

type SQLError struct {
	Code    uint64
	Message string
	Err     error
}

func NewSQLError(code uint64, msg string, err error) error {
	return &SQLError{
		Code:    code,
		Message: msg,
		Err:     err,
	}
}

func (e *SQLError) Error() string {

	if e == nil {
		return ""
	}

	if e.Err != nil {
		return "code:" + strconv.FormatUint(e.Code, 10) + ",message:" + e.Message + ",error:" + e.Err.Error()
	} else {
		return "code:" + strconv.FormatUint(e.Code, 10) + ",message:" + e.Message + ",error:nil"
	}
}

func (e *SQLError) Is(target error) bool {

	if e == nil {
		return false
	}

	if _, ok := target.(*SQLError); ok {
		return true
	}

	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

func (e *SQLError) Unwrap() error {

	if e == nil {
		return nil
	}

	return e.Err
}

type ParamError struct {
	Code    uint64
	Message string
}

func NewParamError(code uint64, text string) error {
	return &ParamError{
		Code:    code,
		Message: text,
	}
}

func (e *ParamError) Error() string {

	if e == nil {
		return ""
	}

	if e.Message == "" {
		e.Message = "some param is nil"
	}

	return "code:" + strconv.FormatUint(e.Code, 10) + "message:" + e.Message
}

func (e *ParamError) Is(target error) bool {

	if e == nil {
		return false
	}

	if _, ok := target.(*ParamError); ok {
		return true
	}

	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

func (e *ParamError) Unwrap() error {
	return nil
}

//----------------- service层错误 -----------------//

type CommonError struct {
	Code      uint64
	Message   string
	RequestId string
	RawErr    error
}

func NewCommonError(code uint64, msg string, requestId string, rawErr error) error {
	return &CommonError{
		Code:      code,
		Message:   msg,
		RequestId: requestId,
		RawErr:    rawErr,
	}
}

func (e *CommonError) Error() string {

	if e == nil {
		return ""
	}

	resp := "code:" + strconv.FormatUint(e.Code, 10) + ",message:" + e.Message

	if e.RequestId != "" {
		resp += ",requestId:" + e.RequestId
	}

	if e.RawErr != nil {
		resp += ",raw:" + e.RawErr.Error()
	}

	return resp
}

func (e *CommonError) Is(target error) bool {
	if e == nil {
		return false
	}

	if _, ok := target.(*CommonError); ok {
		return true
	}
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

func (e *CommonError) Unwrap() error {

	if e == nil {
		return nil
	}

	return e.RawErr
}

//----------------- handler层错误 -----------------//

type GRPCError struct {
	Code    uint64
	Message string
}

func NewGRPCError(code uint64, msg string) error {
	return &GRPCError{
		Code:    code,
		Message: msg,
	}
}

func (e *GRPCError) Error() string {
	if e == nil {
		return ""
	}
	return "grpc error: code:" + strconv.FormatUint(e.Code, 10) + ",message:" + e.Message
}

func (e *GRPCError) Is(target error) bool {
	if e == nil {
		return false
	}
	if _, ok := target.(*GRPCError); ok {
		return true
	}
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

func (e *GRPCError) Unwrap() error {
	return nil
}

var GRPCErrorRegex = regexp.MustCompile(`grpc error: code:(\d+),message:(.+)`)

func ParseToGRPCError(err error) error {
	matches := GRPCErrorRegex.FindStringSubmatch(err.Error())

	if len(matches) != 3 {
		return err
	}
	var code uint64
	if _, err = fmt.Sscanf(matches[1], "%d", &code); err != nil {
		return err
	}
	return NewGRPCError(code, matches[2])
}

//----------------- gateway层错误 -----------------//

type PermissionError struct {
	Code    uint64
	Message string
}

func NewPermError() error {
	return &PermissionError{
		Code:    http.StatusForbidden,
		Message: "无权访问",
	}
}

func (e *PermissionError) Error() string {
	return "code:" + strconv.FormatUint(http.StatusForbidden, 10) + ",message:无权访问"
}

func (e *PermissionError) Is(target error) bool {
	if e == nil {
		return false
	}
	if _, ok := target.(*PermissionError); ok {
		return true
	}

	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

func (e *PermissionError) Unwrap() error {
	return nil
}
