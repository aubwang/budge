package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"budge/internal/access"
	"budge/internal/store"
	"budge/internal/upstream"
	"budge/web"
)

func itoa(i int) string { return strconv.Itoa(i) }

type page struct {
	CSRF, Message, Invitation string
	LoggedIn                  bool
	Inbox                     [][4]string
	Services                  []access.Service
	Devices                   [][2]string
	Permissions               [][8]string
}

var ownerPage = template.Must(template.New("owner.html").ParseFS(web.Files, "owner.html"))

func (s *Server) OwnerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		origin := "http://" + s.OwnerHost
		if r.TLS != nil {
			origin = "https://" + s.OwnerHost
		}
		if r.Host != s.OwnerHost || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			Error(w, 403, "owner_origin_rejected")
			return
		}
		if r.Method == "GET" && (r.URL.Path == "/static/style.css" || r.URL.Path == "/static/poll.js") {
			http.StripPrefix("/static/", http.FileServer(http.FS(web.Files))).ServeHTTP(w, r)
			return
		}
		var owner, csrf string
		c, e := r.Cookie("budge_session")
		if e == nil {
			_ = s.Store.DB.QueryRow("SELECT owner_id,csrf FROM sessions WHERE hash=? AND expires>?", store.Hash(c.Value), time.Now().Unix()).Scan(&owner, &csrf)
		}
		if r.Method == "GET" && r.URL.Path == "/request" {
			if owner == "" {
				Error(w, 401, "owner_login_required")
				return
			}
			s.review(w, r, csrf)
			return
		}
		if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/inbox") {
			if owner == "" {
				csrf = store.ID("")
				http.SetCookie(w, &http.Cookie{Name: "budge_login_csrf", Value: csrf, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 600})
			}
			s.render(w, page{CSRF: csrf, LoggedIn: owner != ""})
			return
		}
		if r.Method != "POST" {
			Error(w, 404, "not_found")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
		if r.ParseForm() != nil {
			Error(w, 400, "invalid_form")
			return
		}
		if r.URL.Path == "/login" {
			pre, e := r.Cookie("budge_login_csrf")
			if e != nil || pre.Value == "" || pre.Value != r.PostForm.Get("csrf") {
				Error(w, 403, "csrf_rejected")
				return
			}
			s.login(w, r)
			return
		}
		if owner == "" {
			Error(w, 401, "owner_login_required")
			return
		}
		if csrf == "" || csrf != r.PostForm.Get("csrf") {
			Error(w, 403, "csrf_rejected")
			return
		}
		var err error
		switch r.URL.Path {
		case "/decision":
			err = s.Decide(owner, r.PostForm.Get("id"), r.PostForm.Get("digest"), r.PostForm.Get("decision"))
		case "/service", "/service-revise":
			err = s.addService(owner, r)
		case "/permission":
			err = s.addPermission(owner, r)
		case "/invite":
			if len(r.PostForm.Get("label")) < 1 || len(r.PostForm.Get("label")) > 100 {
				err = errors.New("invalid device label")
				break
			}
			var inv Invitation
			inv, err = s.Invitation(owner, r.PostForm.Get("label"))
			if err == nil {
				b, _ := json.Marshal(inv)
				s.render(w, page{CSRF: csrf, LoggedIn: true, Invitation: base64.RawURLEncoding.EncodeToString(b)})
				return
			}
		case "/revoke-device":
			err = s.revoke(owner, r.PostForm.Get("id"))
		case "/revoke-permission":
			err = s.revokePermission(owner, r.PostForm.Get("id"))
		case "/disable-service":
			err = s.disableService(owner, r.PostForm.Get("id"))
		case "/logout":
			_, err = s.Store.DB.Exec("DELETE FROM sessions WHERE hash=?", store.Hash(c.Value))
		default:
			Error(w, 404, "not_found")
			return
		}
		if err != nil {
			w.WriteHeader(400)
			s.render(w, page{CSRF: csrf, LoggedIn: true, Message: err.Error()})
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.throttle("login", 10) {
		Error(w, 429, "throttled")
		return
	}
	var id, hash string
	e := s.Store.DB.QueryRow("SELECT id,password_hash FROM owners LIMIT 1").Scan(&id, &hash)
	if e != nil || !store.CheckPassword(hash, r.PostForm.Get("password")) {
		Error(w, 401, "invalid_login")
		return
	}
	token := store.ID("")
	_, e = s.Store.DB.Exec("INSERT INTO sessions(hash,owner_id,csrf,expires) VALUES(?,?,?,?)", store.Hash(token), id, store.ID(""), time.Now().Add(8*time.Hour).Unix())
	if e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "budge_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 8 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) render(w http.ResponseWriter, p page) {
	if p.LoggedIn {
		rows, e := s.Store.DB.Query("SELECT id,device_id,service_id,status FROM requests ORDER BY CASE status WHEN 'pending_approval' THEN 0 WHEN 'queued' THEN 1 WHEN 'dispatching' THEN 2 ELSE 3 END,created DESC,id LIMIT 100")
		if e == nil {
			for rows.Next() {
				var v [4]string
				if rows.Scan(&v[0], &v[1], &v[2], &v[3]) == nil {
					p.Inbox = append(p.Inbox, v)
				}
			}
			rows.Close()
		}
		rows, e = s.Store.DB.Query("SELECT id,label,base_url,revision,auth,private_cidr,request_headers,response_headers FROM services WHERE enabled=1 ORDER BY id")
		if e == nil {
			for rows.Next() {
				var v access.Service
				var req, res string
				if rows.Scan(&v.ID, &v.Label, &v.BaseURL, &v.Revision, &v.Auth, &v.PrivateCIDR, &req, &res) == nil {
					json.Unmarshal([]byte(req), &v.RequestHeaders)
					json.Unmarshal([]byte(res), &v.ResponseHeaders)
					p.Services = append(p.Services, v)
				}
			}
			rows.Close()
		}
		rows, e = s.Store.DB.Query("SELECT id,label FROM devices WHERE revoked=0 ORDER BY id")
		if e == nil {
			for rows.Next() {
				var v [2]string
				if rows.Scan(&v[0], &v[1]) == nil {
					p.Devices = append(p.Devices, v)
				}
			}
			rows.Close()
		}
		rows, e = s.Store.DB.Query("SELECT p.id,p.device_id,p.service_id,p.method,p.path,p.path_kind,p.mode,CASE WHEN p.revision=s.revision AND s.enabled=1 AND (p.expires IS NULL OR p.expires>unixepoch()) THEN 'active' ELSE 'obsolete or expired — review and reissue' END FROM permissions p JOIN services s ON s.id=p.service_id WHERE p.revoked=0")
		if e == nil {
			for rows.Next() {
				var v [8]string
				if rows.Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == nil {
					p.Permissions = append(p.Permissions, v)
				}
			}
			rows.Close()
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ownerPage.Execute(w, p)
}
func (s *Server) addService(owner string, r *http.Request) error {
	f := r.PostForm
	id := f.Get("id")
	if !access.Slug.MatchString(id) || len(f.Get("label")) > 100 {
		return errors.New("invalid service identity")
	}
	if _, e := access.Base(f.Get("base_url")); e != nil {
		return e
	}
	auth, credential, header := f.Get("auth"), f.Get("credential"), http.CanonicalHeaderKey(f.Get("auth_header"))
	if !upstream.HeaderValue(credential) {
		return errors.New("invalid credential")
	}
	switch auth {
	case "none":
		credential = ""
	case "bearer":
		if credential == "" {
			return errors.New("credential required")
		}
	case "header":
		if credential == "" || !upstream.HeaderName(header) || upstream.Reserved(header) {
			return errors.New("invalid authentication header")
		}
	case "basic":
		if !strings.Contains(credential, ":") {
			return errors.New("basic credential requires username:password")
		}
	default:
		return errors.New("unsupported authentication")
	}

	if auth != "header" {
		header = ""
	}
	req, err := headerList(f.Get("request_headers"), []string{"Accept", "Content-Type"}, header)
	if err != nil {
		return err
	}
	res, err := headerList(f.Get("response_headers"), []string{"Content-Type", "Content-Encoding", "Retry-After"}, header)
	if err != nil {
		return err
	}
	if err = access.CIDR(f.Get("private_cidr")); err != nil {
		return err
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return errors.New("storage unavailable")
	}
	defer tx.Rollback()
	revision := 1
	kind := "service_created"
	if r.URL.Path == "/service-revise" {
		if e = tx.QueryRow("SELECT revision FROM services WHERE id=?", id).Scan(&revision); e != nil {
			return errors.New("service not found")
		}
		revision++
		kind = "service_revised"
	}
	encrypted := s.Store.Encrypt("service:"+id+":"+itoa(revision), []byte(credential))
	if revision == 1 {
		_, e = tx.Exec("INSERT INTO services(id,label,base_url,auth,credential,auth_header,request_headers,response_headers,private_cidr) VALUES(?,?,?,?,?,?,?,?,?)", id, f.Get("label"), f.Get("base_url"), auth, encrypted, header, req, res, f.Get("private_cidr"))
	} else {
		_, e = tx.Exec("UPDATE services SET label=?,base_url=?,auth=?,credential=?,auth_header=?,request_headers=?,response_headers=?,private_cidr=?,revision=?,enabled=1 WHERE id=?", f.Get("label"), f.Get("base_url"), auth, encrypted, header, req, res, f.Get("private_cidr"), revision, id)
	}
	if e != nil {
		return errors.New("service could not be saved; verify its ID")
	}
	if revision > 1 {
		if e = cancelRequests(tx, "service_id", id, "service_revised"); e != nil {
			return e
		}
	}
	if e = store.Audit(tx, owner, "", kind, id); e != nil {
		return e
	}
	return tx.Commit()
}
func headerList(raw string, defaults []string, credential string) (string, error) {
	names := defaults
	if raw != "" {
		names = strings.Split(raw, ",")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, n := range names {
		n = http.CanonicalHeaderKey(strings.TrimSpace(n))
		if !upstream.HeaderName(n) || upstream.Reserved(n) || strings.EqualFold(n, credential) {
			return "", errors.New("reserved or invalid application header")
		}
		if !seen[n] {
			out = append(out, n)
			seen[n] = true
		}
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}
func (s *Server) addPermission(owner string, r *http.Request) error {
	f := r.PostForm
	methods, e := access.Methods(f.Get("method"))
	path := f.Get("path")
	if e != nil || !access.Path(path) {
		return errors.New("unsupported method or path")
	}
	kind, mode := f.Get("path_kind"), f.Get("mode")
	if kind == "" {
		kind = "exact"
	}
	if mode == "" {
		mode = "standing"
	}
	if (kind != "exact" && kind != "subtree") || (mode != "standing" && mode != "approval_required") {
		return errors.New("invalid permission kind or mode")
	}
	var expiry any
	if raw := f.Get("expires"); raw != "" {
		t, e := time.Parse(time.RFC3339, raw)
		if e != nil || !t.After(time.Now()) {
			return errors.New("expiry must be a future RFC3339 timestamp")
		}
		expiry = t.Unix()
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	svc, e := access.GetService(tx, f.Get("service"))
	if e != nil || !access.ActiveDevice(tx, f.Get("device")) {
		return errors.New("active service and device required")
	}
	candidate := access.Permission{Method: methods, Path: path, Kind: kind}
	rows, e := tx.Query("SELECT method,path,path_kind FROM permissions WHERE device_id=? AND service_id=? AND revision=? AND revoked=0 AND (expires IS NULL OR expires>?)", f.Get("device"), svc.ID, svc.Revision, time.Now().Unix())
	if e != nil {
		return e
	}
	overlap := false
	for rows.Next() {
		var p access.Permission
		if e = rows.Scan(&p.Method, &p.Path, &p.Kind); e != nil {
			rows.Close()
			return e
		}
		if access.Overlap(candidate, p) {
			overlap = true
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if overlap {
		return errors.New("permission overlaps an active rule")
	}
	id := store.ID("perm_")
	_, e = tx.Exec("INSERT INTO permissions(id,device_id,service_id,revision,method,path,path_kind,mode,expires,created_by_owner_id) VALUES(?,?,?,?,?,?,?,?,?,?)", id, f.Get("device"), svc.ID, svc.Revision, methods, path, kind, mode, expiry, owner)
	if e != nil {
		return errors.New("permission could not be created")
	}
	if e = store.Audit(tx, owner, f.Get("device"), "permission_created", id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Server) revokePermission(owner, id string) error {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE permissions SET revoked=1 WHERE id=?", id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return errors.New("permission not found")
	}
	if e = cancelRequests(tx, "permission_id", id, "permission_revoked"); e != nil {
		return e
	}
	if e = store.Audit(tx, owner, "", "permission_revoked", id); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Server) disableService(owner, id string) error {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE services SET enabled=0,revision=revision+1 WHERE id=?", id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return errors.New("service not found")
	}
	if e = cancelRequests(tx, "service_id", id, "service_disabled"); e != nil {
		return e
	}
	if e = store.Audit(tx, owner, "", "service_disabled", id); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Server) revoke(owner, id string) error {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	res, e := tx.Exec("UPDATE devices SET revoked=1 WHERE id=?", id)
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	if e = cancelRequests(tx, "device_id", id, "device_revoked"); e != nil {
		return e
	}
	if e = store.Audit(tx, owner, id, "device_revoked", id); e != nil {
		return e
	}
	return tx.Commit()
}
