package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"budge/internal/access"
	"budge/internal/store"
	"budge/internal/upstream"
)

type Identity struct {
	URL                           string
	Root, Certificate, PrivateKey []byte
	DeviceID                      string
}
type encryptedIdentity struct {
	Version    int
	Salt, Data []byte
}

func Save(path, pass string, id Identity) error {
	if len(pass) < 12 {
		return errors.New("identity passphrase must have at least 12 characters")
	}
	b, e := json.Marshal(id)
	if e != nil {
		return e
	}
	salt := store.Random(16)
	a, e := store.AEAD(store.Key(pass, salt))
	if e != nil {
		return e
	}
	out, e := json.Marshal(encryptedIdentity{1, salt, store.Seal(a, "budge-client-identity-v1", b)})
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(out); e != nil {
		return e
	}
	return f.Sync()
}
func Load(path, pass string) (Identity, error) {
	var id Identity
	b, e := os.ReadFile(path)
	if e != nil {
		return id, e
	}
	var v encryptedIdentity
	if e = json.Unmarshal(b, &v); e != nil || v.Version != 1 || len(v.Salt) != 16 {
		return id, errors.New("invalid identity file")
	}
	a, e := store.AEAD(store.Key(pass, v.Salt))
	if e != nil {
		return id, e
	}
	b, e = store.Unseal(a, "budge-client-identity-v1", v.Data)
	if e != nil {
		return id, errors.New("cannot unlock identity")
	}
	e = json.Unmarshal(b, &id)
	return id, e
}
func Enroll(ctx context.Context, invitation string) (Identity, error) {
	var id Identity
	var inv struct {
		URL    string `json:"url"`
		Root   []byte `json:"root"`
		Secret string `json:"secret"`
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(invitation))
	if e != nil {
		return id, errors.New("invalid invitation")
	}
	if e = json.Unmarshal(b, &inv); e != nil {
		return id, errors.New("invalid invitation")
	}
	u, e := url.Parse(inv.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return id, errors.New("invalid server origin")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(inv.Root) {
		return id, errors.New("invalid trust root")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return id, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}}, key)
	if e != nil {
		return id, e
	}
	payload, _ := json.Marshal(map[string]any{"secret": inv.Secret, "csr": csr})
	r, e := http.NewRequestWithContext(ctx, "POST", inv.URL+"/enroll", bytes.NewReader(payload))
	if e != nil {
		return id, e
	}
	r.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}, Proxy: nil}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := c.Do(r)
	if e != nil {
		return id, errors.New("enrollment connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return id, errors.New("enrollment rejected")
	}
	var out struct {
		DeviceID    string `json:"device_id"`
		Certificate []byte `json:"certificate"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(&out); e != nil {
		return id, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return id, e
	}
	id = Identity{URL: inv.URL, Root: inv.Root, Certificate: out.Certificate, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), DeviceID: out.DeviceID}
	if _, e = Transport(id); e != nil {
		return Identity{}, e
	}
	return id, nil
}
func Transport(id Identity) (*http.Transport, error) {
	cert, e := tls.X509KeyPair(id.Certificate, id.PrivateKey)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(id.Root) {
		return nil, errors.New("invalid identity root")
	}
	return &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		c, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
		if e != nil {
			return nil, e
		}
		return &upstream.IdleConn{Conn: c}, nil
	}, Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}, DisableCompression: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, nil
}
func Connector(id Identity, host string) (http.Handler, func(), error) {
	h, p, e := net.SplitHostPort(host)
	if e != nil || h != "127.0.0.1" || p == "" {
		return nil, nil, errors.New("connector must bind 127.0.0.1")
	}
	tr, e := Transport(id)
	if e != nil {
		return nil, nil, e
	}
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	slots := make(chan struct{}, 4)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Access-Control-Request-Method") != "" {
			http.Error(w, "local caller rejected", 403)
			return
		}
		if _, _, ok := access.Route(r); !ok {
			http.Error(w, "invalid request", 400)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "connector overloaded", 429)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if e != nil {
			http.Error(w, "body too large", 413)
			return
		}
		req, e := http.NewRequestWithContext(r.Context(), r.Method, id.URL+r.URL.RequestURI(), bytes.NewReader(b))
		if e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		req.GetBody = nil
		req.Header = r.Header.Clone()
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
		res, e := c.Do(req)
		if e != nil {
			http.Error(w, "Budge connection unavailable", 502)
			return
		}
		allowed := make([]string, 0, len(res.Header))
		for k := range res.Header {
			allowed = append(allowed, k)
		}
		if _, e = upstream.Stream(w, res, allowed); e != nil {
			panic(http.ErrAbortHandler)
		}
	})
	return handler, tr.CloseIdleConnections, nil
}
