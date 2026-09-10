package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"budge/internal/access"
)

func Reserved(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate", "proxy-authenticate", "host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "forwarded", "via", "x-real-ip", "x-http-method-override", "x-http-method", "x-method-override":
		return true
	}
	return strings.HasPrefix(n, "x-forwarded-") || strings.HasPrefix(n, "x-budge-") || strings.HasPrefix(n, "budge-") || strings.HasPrefix(n, "sec-") || strings.HasPrefix(n, "x-auth-") || strings.HasPrefix(n, "x-remote-") || strings.HasPrefix(n, "x-ssl-") || strings.HasPrefix(n, "x-client-cert")
}
func HeaderName(n string) bool {
	if n == "" {
		return false
	}
	for _, c := range []byte(n) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
func HeaderValue(s string) bool {
	for _, c := range []byte(s) {
		if c == 127 || c < 32 && c != '\t' {
			return false
		}
	}
	return true
}
func Headers(src http.Header, allowed []string, credentialHeader string) http.Header {
	out := make(http.Header)
	connection := map[string]bool{}
	for _, line := range src.Values("Connection") {
		for _, n := range strings.Split(line, ",") {
			connection[http.CanonicalHeaderKey(strings.TrimSpace(n))] = true
		}
	}
	for _, name := range allowed {
		n := http.CanonicalHeaderKey(name)
		if !HeaderName(n) || Reserved(n) || strings.EqualFold(n, credentialHeader) || connection[n] {
			continue
		}
		for _, v := range src.Values(n) {
			if HeaderValue(v) {
				out.Add(n, v)
			}
		}
	}
	return out
}
func AllowedAddress(a netip.Addr, cidr string) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	// Shared/reserved address space includes non-link-local cloud metadata.
	for _, raw := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(raw).Contains(a) {
			return false
		}
	}
	if a.IsPrivate() {
		p, e := netip.ParsePrefix(cidr)
		return e == nil && p.Contains(a)
	}
	return a.IsGlobalUnicast()
}

// A fresh, HTTP/1-only transport per dispatch has no previously used connection
// on which Go's Transport may automatically replay a request. No proxy, redirects,
// transparent decompression, or request GetBody replay function is used.
func Transport(s access.Service) *http.Transport {
	return &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, errors.New("destination resolution failed")
		}
		for _, ip := range ips {
			if !AllowedAddress(ip, s.PrivateCIDR) {
				return nil, errors.New("destination blocked")
			}
		}
		for _, ip := range ips {
			c, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return &IdleConn{Conn: c}, nil
			}
		}
		return nil, errors.New("destination connection failed")
	}}
}

type IdleConn struct{ net.Conn }

func (c *IdleConn) Read(b []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(5 * time.Minute))
	return c.Conn.Read(b)
}
func (c *IdleConn) Write(b []byte) (int, error) {
	c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return c.Conn.Write(b)
}

// ErrNotSent marks a definite failure before a request could be transmitted.
// It describes the outcome; it does not authorize an automatic retry.
var ErrNotSent = errors.New("request was not sent")

func Send(ctx context.Context, s access.Service, method, target string, h http.Header, body io.Reader, credential []byte, transport *http.Transport) (res *http.Response, err error) {
	var gotConn atomic.Bool
	defer func() {
		if err != nil && !gotConn.Load() {
			err = fmt.Errorf("%w: %w", ErrNotSent, err)
		}
	}()
	// GotConn runs before Transport can write the request, after dialing and TLS.
	// Once it fires, remain conservative even if a later write reports an error:
	// a partial transmission may already have caused an upstream effect.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotConn.Store(true) },
	})
	r, e := http.NewRequestWithContext(ctx, method, target, body)
	if e != nil {
		return nil, e
	}
	r.GetBody = nil
	r.Header = Headers(h, s.RequestHeaders, s.AuthHeader)
	switch s.Auth {
	case "bearer":
		r.Header.Set("Authorization", "Bearer "+string(credential))
	case "header":
		r.Header.Set(s.AuthHeader, string(credential))
	case "basic":
		user, pass, ok := strings.Cut(string(credential), ":")
		if !ok {
			return nil, errors.New("invalid basic credential")
		}
		r.SetBasicAuth(user, pass)
	case "none":
	default:
		return nil, errors.New("unsupported authentication")
	}
	return (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r)
}
func Stream(w http.ResponseWriter, res *http.Response, allowed []string) (int64, error) {
	defer res.Body.Close()
	for k, v := range Headers(res.Header, allowed, "") {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, e := res.Body.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, we := w.Write(buf[:n])
			total += int64(written)
			if we != nil {
				return total, we
			}
			_ = rc.Flush()
		}
		if e == io.EOF {
			return total, nil
		}
		if e != nil {
			return total, e
		}
	}
}
