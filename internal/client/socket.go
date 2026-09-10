package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func ListenSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, errors.New("socket directory must be user-owned with mode 0700")
	}
	l, e := net.Listen("unix", path)
	if e != nil {
		return nil, errors.New("cannot create connector socket; stop any running connector and remove a stale socket if necessary")
	}
	if e = os.Chmod(path, 0600); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
func SocketHandler(id Identity) (http.Handler, func(), error) {
	tr, e := Transport(id)
	if e != nil {
		return nil, nil, e
	}
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := ""
		switch {
		case r.Method == "GET" && r.URL.Path == "/services":
			path = "/device/services"
		case r.Method == "POST" && r.URL.Path == "/request":
			path = "/device/request"
		case r.Method == "POST" && r.URL.Path == "/status":
			path = "/device/status"
		default:
			http.Error(w, "unknown connector operation", 404)
			return
		}
		req, e := http.NewRequestWithContext(r.Context(), r.Method, id.URL+path, http.MaxBytesReader(w, r.Body, 512<<10))
		if e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		res, e := c.Do(req)
		if e != nil {
			http.Error(w, "Budge connection unavailable", 502)
			return
		}
		defer res.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(res.Body, 2<<20))
	}), tr.CloseIdleConnections, nil
}
func SocketClient(path string) (*http.Client, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, errors.New("connector socket unavailable; start budge connect")
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, errors.New("connector socket ownership or mode is unsafe")
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	}}}, nil
}
