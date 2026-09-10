package upstream

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestDestinationConfinement(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "224.0.0.1", "::", "0.0.0.0", "10.0.0.1", "192.168.1.1", "fd00::1"} {
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
