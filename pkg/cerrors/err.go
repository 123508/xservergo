package cerrors

import (
	"net/http"
	"reflect"
	"strconv"
)

//----------------- repo层错误 -----------------//

type SQLError struct {
	Message string
	Err     error
}

func NewSQLError(msg string, err error) error {
	return &SQLError{
		Message: msg,
		Err:     err,
	}
}

func (e *SQLError) Error() string {

	if e == nil {
		return ""
	}

	if e.Err != nil {
		return "message:" + e.Message + ",error:" + e.Err.Error()
	} else {
		return "message:" + e.Message + ",error:nil"
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
	Message string
}

func NewParamError(text string) error {
	return &ParamError{
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

	return "message:" + e.Message
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

	resp := "code:" + strconv.FormatUint(uint64(e.Code), 10) + ",message:" + e.Message

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
	return "code:" + strconv.FormatUint(uint64(e.Code), 10) + ",message:" + e.Message
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
