package server

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"budge/internal/access"
	"budge/internal/store"
	"budge/internal/upstream"
)

type Server struct {
	Store     *store.Store
	OwnerHost string
	ca        authority
	root      *x509.Certificate
	rootKey   any
	mu        sync.Mutex
	throttles map[string][]time.Time
	global    int
	active    map[string]int
	transport func(access.Service) *http.Transport
}

func New(db *store.Store, serverURL, ownerHost, initialPassword string) (*Server, error) {
	s := &Server{Store: db, OwnerHost: ownerHost, throttles: map[string][]time.Time{}, active: map[string]int{}, transport: upstream.Transport}
	if e := s.initTLS(serverURL); e != nil {
		return nil, e
	}
	var n int
	if e := db.DB.QueryRow("SELECT count(*) FROM owners").Scan(&n); e != nil {
		return nil, e
	}
	if n == 0 {
		if len(initialPassword) < 12 {
			return nil, errors.New("first setup requires an owner password of at least 12 characters")
		}
		if _, e := db.DB.Exec("INSERT INTO owners(id,password_hash) VALUES(?,?)", store.ID("owner_"), store.Password(initialPassword)); e != nil {
			return nil, e
		}
	}
	if e := s.recoverDispatches(); e != nil {
		return nil, e
	}
	return s, nil
}
func Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}
func JSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid trailing data")
	}
	return nil
}
func (s *Server) throttle(key string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var live []time.Time
	for _, t := range s.throttles[key] {
		if now.Sub(t) < time.Minute {
			live = append(live, t)
		}
	}
	if len(live) >= limit {
		return false
	}
	s.throttles[key] = append(live, now)
	return true
}
func (s *Server) acquire(device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.global >= 32 || s.active[device] >= 4 {
		return false
	}
	s.global++
	s.active[device]++
	return true
}
func (s *Server) release(device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global--
	s.active[device]--
	if s.active[device] == 0 {
		delete(s.active, device)
	}
}
func (s *Server) device(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", errors.New("device_unauthenticated")
	}
	c := r.TLS.VerifiedChains[0][0]
	now := time.Now()
	if now.Before(c.NotBefore) || !now.Before(c.NotAfter) || !access.ActiveDevice(s.Store.DB, c.Subject.CommonName) {
		return "", errors.New("device_revoked")
	}
	return c.Subject.CommonName, nil
}
func (s *Server) DeviceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enroll" && r.Method == "POST" {
			s.enroll(w, r)
			return
		}
		device, e := s.device(r)
		if e != nil {
			Error(w, 401, e.Error())
			return
		}
		if r.URL.Path == "/device/services" && r.Method == "GET" {
			s.services(w, r, device)
			return
		}
		if r.URL.Path == "/device/request" && r.Method == "POST" {
			s.submit(w, r, device)
			return
		}
		if r.URL.Path == "/device/status" && r.Method == "POST" {
			s.status(w, r, device)
			return
		}
		service, path, ok := access.Route(r)
		if !ok {
			Error(w, 400, "invalid_request")
			return
		}
		if !s.acquire(device) {
			Error(w, 429, "overloaded")
			return
		}
		defer s.release(device)
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if e != nil {
			Error(w, 413, "body_too_large")
			return
		}
		tx, e := s.Store.DB.Begin()
		if e != nil {
			Error(w, 503, "storage_unavailable")
			return
		}
		defer tx.Rollback()
		svc, p, e := access.Authorize(tx, device, service, r.Method, path)
		if e != nil {
			Error(w, 403, "permission_denied")
			return
		}
		if p.Mode != "standing" {
			Error(w, 403, "approval_required")
			return
		}
		target, e := access.Target(svc.BaseURL, path, r.URL.RawQuery)
		if e != nil {
			Error(w, 400, "invalid_request")
			return
		}
		if e = store.Audit(tx, "", device, "http_claim", p.ID); e != nil {
			Error(w, 503, "storage_unavailable")
			return
		}
		if e = tx.Commit(); e != nil {
			Error(w, 503, "storage_unavailable")
			return
		}
		secret, e := s.Store.Decrypt("service:"+svc.ID+":"+itoa(svc.Revision), svc.Credential)
		if e != nil {
			Error(w, 500, "credential_unavailable")
			return
		}
		started := time.Now()
		tr := s.transport(svc)
		defer tr.CloseIdleConnections()
		res, e := upstream.Send(r.Context(), svc, r.Method, target, r.Header, strings.NewReader(string(body)), secret, tr)
		if e != nil {
			s.httpAudit(device, svc.ID, p.ID, r.Method, 502, started, len(body), 0)
			Error(w, 502, "upstream_unavailable")
			return
		}
		res.Header.Del(svc.AuthHeader)
		n, e := upstream.Stream(w, res, svc.ResponseHeaders)
		s.httpAudit(device, svc.ID, p.ID, r.Method, res.StatusCode, started, len(body), n)
		if e != nil {
			panic(http.ErrAbortHandler)
		}
	})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.throttle("enroll", 20) {
		Error(w, 429, "throttled")
		return
	}
	var in struct {
		Secret string `json:"secret"`
		CSR    []byte `json:"csr"`
	}
	if decode(w, r, &in, 32<<10) != nil {
		Error(w, 400, "invalid_enrollment")
		return
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	defer tx.Rollback()
	var id string
	e = tx.QueryRow("SELECT i.device_id FROM invitations i JOIN devices d ON d.id=i.device_id WHERE i.hash=? AND i.used=0 AND i.expires>? AND d.revoked=0", store.Hash(in.Secret), time.Now().Unix()).Scan(&id)
	if e != nil {
		Error(w, 403, "invitation_invalid")
		return
	}
	cert, e := s.issue(id, in.CSR)
	if e != nil {
		Error(w, 400, "invalid_csr")
		return
	}
	if _, e = tx.Exec("UPDATE invitations SET used=1 WHERE hash=?", store.Hash(in.Secret)); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	if e = store.Audit(tx, "", id, "enrolled", id); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	if e = tx.Commit(); e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	JSON(w, map[string]any{"device_id": id, "certificate": cert})
}

func (s *Server) httpAudit(device, service, permission, method string, status int, started time.Time, req int, res int64) {
	_, _ = s.Store.DB.Exec("INSERT INTO http_events(device_id,service_id,permission_id,method,status,duration_ms,request_bytes,response_bytes) VALUES(?,?,?,?,?,?,?,?)", device, service, permission, method, status, time.Since(started).Milliseconds(), req, res)
}
func (s *Server) services(w http.ResponseWriter, r *http.Request, device string) {
	rows, e := s.Store.DB.Query("SELECT s.id,s.label,p.id,p.method,p.path,p.path_kind,p.mode,p.expires FROM services s JOIN permissions p ON p.service_id=s.id WHERE p.device_id=? AND s.enabled=1 AND p.revision=s.revision AND p.revoked=0 AND (p.expires IS NULL OR p.expires>?) ORDER BY s.id,p.id", device, time.Now().Unix())
	if e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	defer rows.Close()
	scopes := []map[string]any{}
	for rows.Next() {
		var service, label, id, methods, path, kind, mode string
		var expires sql.NullInt64
		if e = rows.Scan(&service, &label, &id, &methods, &path, &kind, &mode, &expires); e != nil {
			Error(w, 503, "storage_unavailable")
			return
		}
		entry := map[string]any{"service": service, "label": label, "permission_id": id, "methods": strings.Split(methods, ","), "path": path, "path_kind": kind, "mode": mode}
		if expires.Valid {
			entry["expires_at"] = time.Unix(expires.Int64, 0).UTC().Format(time.RFC3339)
		}
		scopes = append(scopes, entry)
	}
	JSON(w, map[string]any{"scopes": scopes})
}
