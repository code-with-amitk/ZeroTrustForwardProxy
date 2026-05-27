package utils

import (
	"net/http"
	"net/http/httputil"
	"runtime"
)

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	return runtime.FuncForPC(pc).Name() + "()"
}

func DumpHttpRequest(r *http.Request) string {
	dump, err := httputil.DumpRequest(r, true)
	if err == nil {
		return string(dump)
	}
	return ""
}
