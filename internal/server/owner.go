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
)

func itoa(i int) string { return strconv.Itoa(i) }

type page struct {
	CSRF, Message, Invitation string
	LoggedIn                  bool
	Services                  []access.Service
	Devices                   [][2]string
	Permissions               [][5]string
}

var ownerPage = template.Must(template.New("owner").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Budge</title><style>body{font:16px system-ui;max-width:950px;margin:3rem auto;padding:0 1rem;background:#f5f5ef;color:#172c27}section{background:white;border:1px solid #d0d8cf;padding:1.5rem;margin:1.5rem 0;border-radius:12px}label{display:block;margin:.7rem 0}input,select,textarea,button{font:inherit;padding:.5rem;max-width:95%}input{min-width:20rem}button{background:#173f34;color:white;border:0;border-radius:4px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{display:block;color:#52635c}</style><h1>Budge</h1><p>Device access. Credentials stay here.</p>{{if .Message}}<p role="status">{{.Message}}</p>{{end}}{{if not .LoggedIn}}<section><h2>Owner sign in</h2><form method="post" action="/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Password <input name="password" type="password" required autocomplete="current-password"></label><button>Sign in</button></form></section>{{else}}
<section><h2>Services</h2>{{range .Services}}<p><b>{{.ID}}</b> — {{.Label}} · revision {{.Revision}} · {{.BaseURL}} · credential: {{.Auth}} (write only)</p>{{else}}<p>No services yet.</p>{{end}}<form method="post" action="/service"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Service ID <input name="id" required placeholder="openrouter"></label><label>Account label <input name="label" required></label><label>HTTPS base URL <input name="base_url" required placeholder="https://openrouter.ai/api"></label><label>Authentication <select name="auth"><option>bearer</option><option>none</option><option>header</option><option>basic</option></select></label><label>Credential <input name="credential" type="password" autocomplete="new-password"><small>For basic authentication, enter username:password.</small></label><label>Credential header (header auth only) <input name="auth_header"></label><button>Add service</button></form></section>
<section><h2>Devices</h2>{{range .Devices}}<p>{{index . 1}} · <code>{{index . 0}}</code></p><form method="post" action="/revoke-device"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{index . 0}}"><button>Revoke device</button></form>{{end}}<form method="post" action="/invite"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Device label <input name="label" required></label><button>Create 5-minute invitation</button></form>{{if .Invitation}}<p>Transfer privately and paste at the hidden enrollment prompt. This invitation works once.</p><textarea readonly rows="8" cols="80">{{.Invitation}}</textarea>{{end}}</section>
<section><h2>Standing permissions</h2>{{range .Permissions}}<p>{{index . 1}} → {{index . 2}} · {{index . 3}} {{index . 4}}</p>{{end}}<form method="post" action="/permission"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Device <select name="device">{{range .Devices}}<option value="{{index . 0}}">{{index . 1}}</option>{{end}}</select></label><label>Service <select name="service">{{range .Services}}<option>{{.ID}}</option>{{end}}</select></label><label>Method <select name="method"><option>POST</option><option>GET</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option></select></label><label>Exact path <input name="path" required placeholder="/v1/chat/completions"></label><small>No expiry. Exact method/path only. Query values and body fields are unrestricted.</small><button>Grant standing permission</button></form></section><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>{{end}}</html>`))

func (s *Server) OwnerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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
		var owner, csrf string
		c, e := r.Cookie("budge_session")
		if e == nil {
			_ = s.Store.DB.QueryRow("SELECT owner_id,csrf FROM sessions WHERE hash=? AND expires>?", store.Hash(c.Value), time.Now().Unix()).Scan(&owner, &csrf)
		}
		if r.Method == "GET" && r.URL.Path == "/" {
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
		case "/service":
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
		rows, e := s.Store.DB.Query("SELECT id,label,base_url,revision,auth FROM services WHERE enabled=1 ORDER BY id")
		if e == nil {
			for rows.Next() {
				var v access.Service
				if rows.Scan(&v.ID, &v.Label, &v.BaseURL, &v.Revision, &v.Auth) == nil {
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
		rows, e = s.Store.DB.Query("SELECT id,device_id,service_id,method,path FROM permissions WHERE revoked=0")
		if e == nil {
			for rows.Next() {
				var v [5]string
				if rows.Scan(&v[0], &v[1], &v[2], &v[3], &v[4]) == nil {
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
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return errors.New("storage unavailable")
	}
	defer tx.Rollback()
	_, e = tx.Exec("INSERT INTO services(id,label,base_url,auth,credential,auth_header) VALUES(?,?,?,?,?,?)", id, f.Get("label"), f.Get("base_url"), auth, s.Store.Encrypt("service:"+id+":1", []byte(credential)), header)
	if e != nil {
		return errors.New("service could not be created; choose a unique ID")
	}
	if e = store.Audit(tx, owner, "", "service_created", id); e != nil {
		return errors.New("audit unavailable")
	}
	return tx.Commit()
}
func (s *Server) addPermission(owner string, r *http.Request) error {
	f := r.PostForm
	method, path := f.Get("method"), f.Get("path")
	if !access.Method(method) || !access.Path(path) {
		return errors.New("unsupported method or path")
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
	var n int
	e = tx.QueryRow("SELECT count(*) FROM permissions WHERE device_id=? AND service_id=? AND revision=? AND method=? AND path=? AND revoked=0 AND (expires IS NULL OR expires>?)", f.Get("device"), svc.ID, svc.Revision, method, path, time.Now().Unix()).Scan(&n)
	if e != nil {
		return e
	}
	if n > 0 {
		return errors.New("permission overlaps an active rule")
	}
	id := store.ID("perm_")
	_, e = tx.Exec("INSERT INTO permissions(id,device_id,service_id,revision,method,path,created_by_owner_id) VALUES(?,?,?,?,?,?,?)", id, f.Get("device"), svc.ID, svc.Revision, method, path, owner)
	if e != nil {
		return errors.New("permission could not be created")
	}
	if e = store.Audit(tx, owner, f.Get("device"), "permission_created", id); e != nil {
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
	if e = store.Audit(tx, owner, id, "device_revoked", id); e != nil {
		return e
	}
	return tx.Commit()
}
