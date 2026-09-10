package client

import (
	"budge/internal/store"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Renewal struct {
	mu        sync.Mutex
	id        Identity
	cert      tls.Certificate
	transport *http.Transport
}

func NewRenewal(id Identity, tr *http.Transport) (*Renewal, error) {
	cert, e := tls.X509KeyPair(id.Certificate, id.PrivateKey)
	if e != nil {
		return nil, e
	}
	live := &Renewal{id: id, cert: cert, transport: tr}
	tr.TLSClientConfig.Certificates = nil
	tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		live.mu.Lock()
		defer live.mu.Unlock()
		cert := live.cert
		return &cert, nil
	}
	return live, nil
}
func (l *Renewal) Refresh(ctx context.Context, path, pass string) error {
	l.mu.Lock()
	id := l.id
	l.mu.Unlock()
	block, _ := pem.Decode(id.Certificate)
	if block == nil {
		return errors.New("invalid local certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	if time.Until(cert.NotAfter) > 7*24*time.Hour {
		return nil
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("device certificate expired; obtain a new invitation")
	}
	keyBlock, _ := pem.Decode(id.PrivateKey)
	if keyBlock == nil {
		return errors.New("invalid local key")
	}
	key, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		return e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(map[string]any{"csr": csr})
	r, e := http.NewRequestWithContext(ctx, "POST", id.URL+"/device/renew", bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	res, e := (&http.Client{Transport: l.transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r)
	if e != nil {
		return errors.New("certificate renewal connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("certificate renewal rejected; check device status")
	}
	var out struct {
		DeviceID    string `json:"device_id"`
		Certificate []byte `json:"certificate"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(&out); e != nil || out.DeviceID != id.DeviceID {
		return errors.New("invalid renewed identity")
	}
	next, e := tls.X509KeyPair(out.Certificate, id.PrivateKey)
	if e != nil {
		return e
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(id.Root)
	leaf, e := x509.ParseCertificate(next.Certificate[0])
	if e != nil {
		return e
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil || leaf.Subject.CommonName != id.DeviceID {
		return errors.New("renewed certificate verification failed")
	}
	id.Certificate = out.Certificate
	// Persist before exposing the renewed certificate to new handshakes.
	temp := filepath.Join(filepath.Dir(path), ".renew-"+store.ID(""))
	if e = Save(temp, pass, id); e != nil {
		return e
	}
	defer os.Remove(temp)
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return e
	}
	l.mu.Lock()
	l.id = id
	l.cert = next
	l.mu.Unlock()
	l.transport.CloseIdleConnections()
	return nil
}
