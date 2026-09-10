package access

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var Slug = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

func Path(p string) bool {
	if p == "" || p[0] != '/' || strings.ContainsAny(p, "%\\?#") || strings.Contains(p, "//") {
		return false
	}
	for _, c := range []byte(p) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/-._~!$&'()*+,;=:@", rune(c))) {
			return false
		}
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}
func Method(m string) bool {
	if m == "" || m == "*" || len(m) > 64 || strings.EqualFold(m, "CONNECT") || strings.EqualFold(m, "TRACE") {
		return false
	}
	for _, c := range []byte(m) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
func Base(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || (u.Path != "" && !Path(u.Path)) {
		return nil, errors.New("service requires an HTTPS origin and conservative base path")
	}
	return u, nil
}
func Target(base, path, query string) (string, error) {
	u, e := Base(base)
	if e != nil || !Path(path) {
		return "", errors.New("unsupported path")
	}
	for _, c := range []byte(query) {
		if c < 33 || c > 126 || c == '#' {
			return "", errors.New("invalid raw query")
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = query
	return u.String(), nil
}
func Route(r *http.Request) (service, path string, ok bool) {
	if r.URL.IsAbs() || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, "/s/") || !Method(r.Method) || r.Header.Get("Upgrade") != "" {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return
	}
	service, path = rest[:i], rest[i:]
	return service, path, Slug.MatchString(service) && Path(path)
}
func CIDR(raw string) error {
	if raw == "" {
		return nil
	}
	p, e := netip.ParsePrefix(raw)
	if e != nil || !p.Addr().IsPrivate() || p.Bits() < 8 {
		return errors.New("private destination must be an explicit private CIDR")
	}
	return nil
}

type Service struct {
	ID, Label, BaseURL, Auth, AuthHeader, PrivateCIDR string
	Revision                                          int
	Credential                                        []byte
	RequestHeaders, ResponseHeaders                   []string
}
type Permission struct {
	ID, DeviceID, ServiceID, Method, Path, Kind, Mode, Owner string
	Revision                                                 int
	Expires                                                  sql.NullInt64
}
type Querier interface {
	QueryRow(string, ...any) *sql.Row
	Query(string, ...any) (*sql.Rows, error)
}

func GetService(q Querier, id string) (Service, error) {
	var s Service
	var req, res string
	e := q.QueryRow("SELECT id,label,base_url,auth,auth_header,private_cidr,revision,credential,request_headers,response_headers FROM services WHERE id=? AND enabled=1", id).Scan(&s.ID, &s.Label, &s.BaseURL, &s.Auth, &s.AuthHeader, &s.PrivateCIDR, &s.Revision, &s.Credential, &req, &res)
	if e == nil {
		e = json.Unmarshal([]byte(req), &s.RequestHeaders)
	}
	if e == nil {
		e = json.Unmarshal([]byte(res), &s.ResponseHeaders)
	}
	return s, e
}
func ActiveDevice(q Querier, id string) bool {
	var n int
	return q.QueryRow("SELECT 1 FROM devices WHERE id=? AND revoked=0", id).Scan(&n) == nil
}
func Match(p Permission, method, path string) bool {
	return HasMethod(p.Method, method) && (path == p.Path || (p.Kind == "subtree" && strings.HasPrefix(path, strings.TrimSuffix(p.Path, "/")+"/")))
}
func Authorize(q Querier, device, service, method, path string) (Service, Permission, error) {
	if !ActiveDevice(q, device) {
		return Service{}, Permission{}, errors.New("device_revoked")
	}
	s, e := GetService(q, service)
	if e != nil {
		return s, Permission{}, errors.New("permission_denied")
	}
	rows, e := q.Query("SELECT id,method,path,path_kind,mode,created_by_owner_id,expires FROM permissions WHERE device_id=? AND service_id=? AND revision=? AND revoked=0 AND (expires IS NULL OR expires>?)", device, service, s.Revision, time.Now().Unix())
	if e != nil {
		return s, Permission{}, e
	}
	defer rows.Close()
	for rows.Next() {
		p := Permission{DeviceID: device, ServiceID: service, Revision: s.Revision}
		if e = rows.Scan(&p.ID, &p.Method, &p.Path, &p.Kind, &p.Mode, &p.Owner, &p.Expires); e != nil {
			return s, p, e
		}
		if Match(p, method, path) {
			return s, p, nil
		}
	}
	return s, Permission{}, errors.New("permission_denied")
}

func HasMethod(methods, method string) bool {
	for _, m := range strings.Split(methods, ",") {
		if m == method {
			return true
		}
	}
	return false
}
func Methods(raw string) (string, error) {
	seen := map[string]bool{}
	var out []string
	for _, m := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if !Method(m) || seen[m] {
			return "", errors.New("invalid or duplicate method")
		}
		seen[m] = true
		out = append(out, m)
	}
	if len(out) == 0 {
		return "", errors.New("methods required")
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}
func Overlap(a, b Permission) bool {
	for _, m := range strings.Split(a.Method, ",") {
		if !HasMethod(b.Method, m) {
			continue
		}
		if Match(a, m, b.Path) || Match(b, m, a.Path) {
			return true
		}
	}
	return false
}
