package server

import (
	"budge/internal/access"
	"budge/internal/store"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

func (s *Server) renew(w http.ResponseWriter, r *http.Request, device string) {
	if !s.throttle("renew:"+device, 5) {
		Error(w, 429, "throttled")
		return
	}
	if time.Until(r.TLS.VerifiedChains[0][0].NotAfter) > 7*24*time.Hour {
		Error(w, 409, "renewal_not_due")
		return
	}
	var in struct {
		CSR []byte `json:"csr"`
	}
	if decode(w, r, &in, 32<<10) != nil {
		Error(w, 400, "invalid_csr")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	defer tx.Rollback()
	if !access.ActiveDevice(tx, device) {
		Error(w, 401, "device_revoked")
		return
	}
	cert, e := s.issue(device, in.CSR)
	if e != nil {
		Error(w, 400, "invalid_csr")
		return
	}
	block, _ := pem.Decode(cert)
	parsed, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		Error(w, 500, "certificate_failed")
		return
	}
	if _, e = tx.Exec("UPDATE devices SET certificate_serial=?,certificate_expires=? WHERE id=?", parsed.SerialNumber.String(), parsed.NotAfter.Unix(), device); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	if e = store.Audit(tx, "", device, "certificate_renewed", device); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	if e = tx.Commit(); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	JSON(w, map[string]any{"device_id": device, "certificate": cert})
}
func (s *Server) renewLeaf() error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	u, e := url.Parse(s.ca.URL)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: serial(), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{u.Hostname()}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, s.root, &key.PublicKey, s.rootKey)
	if e != nil {
		return e
	}
	next := s.ca
	next.Leaf = certPEM(der)
	next.LeafKey = keyPEM(key)
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if _, e = s.Store.DB.Exec("UPDATE metadata SET value=? WHERE key='authority'", s.Store.Encrypt("authority", b)); e != nil {
		return e
	}
	s.ca.Leaf = next.Leaf
	s.ca.LeafKey = next.LeafKey
	return nil
}
func (s *Server) currentCertificate() (tls.Certificate, error) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	block, _ := pem.Decode(s.ca.Leaf)
	if block == nil {
		return tls.Certificate{}, errors.New("invalid server leaf")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return tls.Certificate{}, e
	}
	if time.Until(cert.NotAfter) <= 7*24*time.Hour {
		if e = s.renewLeaf(); e != nil {
			return tls.Certificate{}, e
		}
	}
	return tls.X509KeyPair(s.ca.Leaf, s.ca.LeafKey)
}
