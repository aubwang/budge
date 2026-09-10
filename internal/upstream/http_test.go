package upstream

import (
	"budge/internal/access"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestDestinationConfinement(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "64:ff9b::a9fe:a9fe", "fe80::1", "224.0.0.1", "::", "0.0.0.0", "10.0.0.1", "192.168.1.1", "fd00::1"} {
		if AllowedAddress(netip.MustParseAddr(ip), "") {
			t.Errorf("blocked address allowed %s", ip)
		}
	}
	if !AllowedAddress(netip.MustParseAddr("10.1.2.3"), "10.1.2.0/24") {
		t.Fatal("explicit private exception rejected")
	}
	if AllowedAddress(netip.MustParseAddr("169.254.169.254"), "169.254.0.0/16") {
		t.Fatal("metadata exception accepted")
	}
}
func TestHeaderConfinement(t *testing.T) {
	h := http.Header{"Connection": {"X-Visible"}, "X-Visible": {"strip"}, "Authorization": {"client"}, "X-Api-Key": {"client"}, "Content-Type": {"text/plain"}, "X-Forwarded-For": {"forged"}, "X-Budge-Device": {"forged"}, "Set-Cookie": {"strip"}, "X-Http-Method-Override": {"DELETE"}}
	allowed := []string{}
	for k := range h {
		allowed = append(allowed, k)
	}
	got := Headers(h, allowed, "X-Api-Key")
	if len(got) != 1 || got.Get("Content-Type") != "text/plain" {
		t.Fatalf("reserved headers escaped: %v", got)
	}
}
func TestStaticAuthenticationKinds(t *testing.T) {
	for _, kind := range []string{"none", "bearer", "header", "basic"} {
		t.Run(kind, func(t *testing.T) {
			u := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "none":
					if r.Header.Get("Authorization") != "" {
						t.Error("client authentication forwarded")
					}
				case "bearer":
					if r.Header.Get("Authorization") != "Bearer synthetic-token" {
						t.Error("bearer missing")
					}
				case "header":
					if r.Header.Get("X-Api-Key") != "synthetic-token" {
						t.Error("header missing")
					}
				case "basic":
					user, pass, ok := r.BasicAuth()
					if !ok || user != "synthetic" || pass != "password" {
						t.Error("basic missing")
					}
				}
				w.WriteHeader(204)
			}))
			defer u.Close()
			credential := []byte("synthetic-token")
			if kind == "basic" {
				credential = []byte("synthetic:password")
			}
			s := access.Service{Auth: kind, AuthHeader: "X-Api-Key", RequestHeaders: []string{"Accept", "Content-Type"}}
			tr := u.Client().Transport.(*http.Transport).Clone()
			defer tr.CloseIdleConnections()
			res, e := Send(context.Background(), s, "POST", u.URL, http.Header{"Authorization": {"Bearer budge-local"}}, strings.NewReader("x"), credential, tr)
			if e != nil {
				t.Fatal(e)
			}
			res.Body.Close()
			if res.StatusCode != 204 {
				t.Fatal("authentication test failed")
			}
		})
	}
}
