package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"time"

	"budge/internal/store"
)

type authority struct {
	Root, RootKey, Leaf, LeafKey []byte
	URL                          string
}

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func keyPEM(k *ecdsa.PrivateKey) []byte {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		panic(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func certPEM(b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}) }
func (s *Server) initTLS(serverURL string) error {
	u, e := url.Parse(serverURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server URL must be an HTTPS origin")
	}
	var encrypted []byte
	e = s.Store.DB.QueryRow("SELECT value FROM metadata WHERE key='authority'").Scan(&encrypted)
	if e == nil {
		b, e := s.Store.Decrypt("authority", encrypted)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &s.ca); e != nil {
			return e
		}
		if s.ca.URL != serverURL {
			return errors.New("server URL differs from initialized identity")
		}
	} else if e == sql.ErrNoRows {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		now := time.Now()
		root := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Budge trust root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, e := x509.CreateCertificate(rand.Reader, root, root, &k.PublicKey, k)
		if e != nil {
			return e
		}
		s.ca = authority{Root: certPEM(der), RootKey: keyPEM(k), URL: serverURL}
	} else {
		return e
	}
	rootBlock, _ := pem.Decode(s.ca.Root)
	keyBlock, _ := pem.Decode(s.ca.RootKey)
	if rootBlock == nil || keyBlock == nil {
		return errors.New("invalid authority")
	}
	s.root, e = x509.ParseCertificate(rootBlock.Bytes)
	if e != nil {
		return e
	}
	s.rootKey, e = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		return e
	}
	renew := true
	if block, _ := pem.Decode(s.ca.Leaf); block != nil {
		if c, e := x509.ParseCertificate(block.Bytes); e == nil && time.Until(c.NotAfter) > 7*24*time.Hour {
			renew = false
		}
	}
	if renew {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		s.ca.Leaf = certPEM(der)
		s.ca.LeafKey = keyPEM(key)
	}
	b, e := json.Marshal(s.ca)
	if e != nil {
		return e
	}
	_, e = s.Store.DB.Exec("INSERT INTO metadata(key,value) VALUES('authority',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", s.Store.Encrypt("authority", b))
	return e
}
func (s *Server) TLSConfig() (*tls.Config, error) {
	cert, e := tls.X509KeyPair(s.ca.Leaf, s.ca.LeafKey)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.ca.Root)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}, nil
}
func (s *Server) issue(device string, csrDER []byte) ([]byte, error) {
	csr, e := x509.ParseCertificateRequest(csrDER)
	if e != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid CSR")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("CSR requires P-256 key")
	}
	c := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: device}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, c, s.root, csr.PublicKey, s.rootKey)
	if e != nil {
		return nil, e
	}
	return certPEM(der), nil
}

type Invitation struct {
	URL    string `json:"url"`
	Root   []byte `json:"root"`
	Secret string `json:"secret"`
}

func (s *Server) Invitation(owner, label string) (Invitation, error) {
	id, secret := store.ID("dev_"), store.ID("")
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return Invitation{}, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO devices(id,label) VALUES(?,?)", id, label); e != nil {
		return Invitation{}, e
	}
	if _, e = tx.Exec("INSERT INTO invitations(hash,device_id,expires) VALUES(?,?,?)", store.Hash(secret), id, time.Now().Add(5*time.Minute).Unix()); e != nil {
		return Invitation{}, e
	}
	if e = store.Audit(tx, owner, id, "invitation_created", id); e != nil {
		return Invitation{}, e
	}
	if e = tx.Commit(); e != nil {
		return Invitation{}, e
	}
	return Invitation{s.ca.URL, s.ca.Root, secret}, nil
}
