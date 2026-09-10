package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"budge/internal/access"
	"budge/internal/client"
	"budge/internal/store"
)

const fixtureUnlock = "synthetic-unlock-password"
const fixtureOwner = "synthetic-owner-password"
const fixtureCredential = "synthetic-upstream-credential-DO-NOT-LEAK"

type harness struct {
	t                 *testing.T
	db                *store.Store
	s                 *Server
	up, device, owner *httptest.Server
	browser           *http.Client
	csrf, dir         string
	hits              atomic.Int32
}

func newHarness(t *testing.T, handle http.HandlerFunc) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir()}
	h.up = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+fixtureCredential {
			t.Errorf("upstream authentication mismatch")
		}
		if handle != nil {
			handle(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "must-not-forward=1")
		w.WriteHeader(201)
		io.Copy(w, r.Body)
	}))
	t.Cleanup(h.up.Close)
	var e error
	h.db, e = store.Open(filepath.Join(h.dir, "budge.db"), fixtureUnlock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(h.db.Close)
	h.device = httptest.NewUnstartedServer(nil)
	h.owner = httptest.NewUnstartedServer(nil)
	h.s, e = New(h.db, "https://"+h.device.Listener.Addr().String(), h.owner.Listener.Addr().String(), fixtureOwner)
	if e != nil {
		t.Fatal(e)
	}
	// The only loopback/trust exception lives in this _test.go file; no production
	// configuration or environment variable enables it.
	h.s.transport = func(access.Service) *http.Transport {
		tr := h.up.Client().Transport.(*http.Transport).Clone()
		tr.DisableKeepAlives = true
		tr.DisableCompression = true
		tr.ForceAttemptHTTP2 = false
		return tr
	}
	h.device.Config.Handler = h.s.DeviceHandler()
	h.device.TLS, e = h.s.TLSConfig()
	if e != nil {
		t.Fatal(e)
	}
	h.device.StartTLS()
	t.Cleanup(h.device.Close)
	h.owner.Config.Handler = h.s.OwnerHandler()
	h.owner.Start()
	t.Cleanup(h.owner.Close)
	jar, _ := cookiejar.New(nil)
	h.browser = &http.Client{Jar: jar}
	h.csrf = h.getCSRF()
	h.post("/login", url.Values{"password": {fixtureOwner}}, 200)
	h.csrf = h.getCSRF()
	return h
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) getCSRF() string {
	h.t.Helper()
	r, e := h.browser.Get(h.owner.URL)
	if e != nil {
		h.t.Fatal(e)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	m := csrfRE.FindSubmatch(b)
	if len(m) != 2 {
		h.t.Fatal("missing CSRF")
	}
	return string(m[1])
}
func (h *harness) post(path string, v url.Values, want int) string {
	h.t.Helper()
	v.Set("csrf", h.csrf)
	r, e := h.browser.PostForm(h.owner.URL+path, v)
	if e != nil {
		h.t.Fatal(e)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != want {
		h.t.Fatalf("owner %s: got %d want %d: %s", path, r.StatusCode, want, b)
	}
	if strings.Contains(string(b), fixtureCredential) {
		h.t.Fatal("owner credential readback")
	}
	return string(b)
}
func (h *harness) addService() {
	h.post("/service", url.Values{"id": {"mock"}, "label": {"Synthetic account"}, "base_url": {h.up.URL + "/api"}, "auth": {"bearer"}, "credential": {fixtureCredential}}, 200)
}
func (h *harness) enroll() client.Identity {
	h.t.Helper()
	var owner string
	if e := h.db.DB.QueryRow("SELECT id FROM owners").Scan(&owner); e != nil {
		h.t.Fatal(e)
	}
	inv, e := h.s.Invitation(owner, "Synthetic device")
	if e != nil {
		h.t.Fatal(e)
	}
	b, _ := json.Marshal(inv)
	encoded := base64.RawURLEncoding.EncodeToString(b)
	id, e := client.Enroll(context.Background(), encoded)
	if e != nil {
		h.t.Fatal(e)
	}
	if _, e = client.Enroll(context.Background(), encoded); e == nil {
		h.t.Fatal("invitation reuse accepted")
	}
	return id
}
func (h *harness) grant(id client.Identity, path string) {
	h.post("/permission", url.Values{"device": {id.DeviceID}, "service": {"mock"}, "method": {"POST"}, "path": {path}}, 200)
}
func (h *harness) connector(id client.Identity) *httptest.Server {
	h.t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	handler, close, e := client.Connector(id, srv.Listener.Addr().String())
	if e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(close)
	srv.Config.Handler = handler
	srv.Start()
	h.t.Cleanup(srv.Close)
	return srv
}
func TestSlice1AuthenticatedRoundTrip(t *testing.T) {
	body := "{\n  \"message\": \"synthetic\"\n}"
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/api/v1/write?x=1&x=2" {
			t.Errorf("request URI changed: %s", r.URL.RequestURI())
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Budge-Device") != "" {
			t.Error("reserved header forwarded")
		}
		w.Header().Set("Set-Cookie", "blocked")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		io.Copy(w, r.Body)
	})
	h.addService()
	id := h.enroll()
	conn := h.connector(id)
	call := func(path string, want int) {
		t.Helper()
		r, _ := http.NewRequest("POST", conn.URL+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer budge-local")
		r.Header.Set("Cookie", "secret=blocked")
		r.Header.Set("X-Forwarded-For", "forged")
		r.Header.Set("X-Budge-Device", "forged")
		res, e := conn.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("got %d want %d: %s", res.StatusCode, want, b)
		}
		if strings.Contains(string(b), fixtureCredential) || res.Header.Get("Set-Cookie") != "" {
			t.Fatal("credential/cookie leak")
		}
		if want == 201 && string(b) != body {
			t.Fatal("body changed")
		}
	}
	call("/s/mock/v1/write?x=1&x=2", 403)
	h.grant(id, "/v1/write")
	call("/s/mock/v1/write?x=1&x=2", 201)
	call("/s/mock/v1/other", 403)
	h.post("/revoke-device", url.Values{"id": {id.DeviceID}}, 200)
	call("/s/mock/v1/write?x=1&x=2", 401)
	if h.hits.Load() != 1 {
		t.Fatalf("unauthorized dispatch: %d", h.hits.Load())
	}
	unauthed := h.device.Client()
	res, e := unauthed.Post(h.device.URL+"/s/mock/v1/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("unenrolled accepted")
	}
	identityPath := filepath.Join(h.dir, "device.identity")
	if e = client.Save(identityPath, "synthetic-local-password", id); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Load(identityPath, "incorrect-password"); e == nil {
		t.Fatal("wrong identity passphrase accepted")
	}
	loaded, e := client.Load(identityPath, "synthetic-local-password")
	if e != nil || loaded.DeviceID != id.DeviceID {
		t.Fatal("identity roundtrip failed")
	}
	raw, _ := os.ReadFile(identityPath)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("plaintext identity")
	}
	for _, file := range []string{"budge.db", "budge.db-wal"} {
		raw, _ = os.ReadFile(filepath.Join(h.dir, file))
		if strings.Contains(string(raw), fixtureCredential) || strings.Contains(string(raw), "PRIVATE KEY") {
			t.Fatal("plaintext persistent secret")
		}
	}
}
func TestSlice1RestartAndOwnerIsolation(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	tc, e := client.Transport(id)
	if e != nil {
		t.Fatal(e)
	}
	c := &http.Client{Transport: tc}
	defer tc.CloseIdleConnections()
	res, e := c.Post(h.owner.URL+"/invite", "application/x-www-form-urlencoded", strings.NewReader("label=forged"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("device authenticated as owner")
	}
	r, _ := http.NewRequest("POST", h.owner.URL+"/invite", strings.NewReader("label=bad&csrf="+h.csrf))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.invalid")
	res, e = h.browser.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("CSRF origin accepted")
	}
	if _, e = store.Open(filepath.Join(h.dir, "budge.db"), fixtureUnlock); e == nil {
		t.Fatal("second instance accepted")
	}
	h.db.Close()
	if _, e = store.Open(filepath.Join(h.dir, "budge.db"), "incorrect-password"); e == nil {
		t.Fatal("wrong unlock accepted")
	}
	db, e := store.Open(filepath.Join(h.dir, "budge.db"), fixtureUnlock)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, p, e := access.Authorize(db.DB, id.DeviceID, "mock", "POST", "/write")
	if e != nil || p.Expires.Valid {
		t.Fatal("standing permission did not survive restart")
	}
}
func TestSlice1ConnectorRejectsBrowser(t *testing.T) {
	h := newHarness(t, nil)
	id := h.enroll()
	conn := h.connector(id)
	for _, header := range []string{"Origin", "Sec-Fetch-Site", "Access-Control-Request-Method"} {
		r, _ := http.NewRequest("POST", conn.URL+"/s/mock/write", nil)
		r.Header.Set(header, "browser")
		res, e := conn.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("accepted browser %s", header)
		}
	}
	r, _ := http.NewRequest("POST", conn.URL+"/s/mock/write", nil)
	r.Host = "evil.invalid"
	res, e := conn.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("forged host accepted")
	}
}
