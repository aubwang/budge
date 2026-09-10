package access

import "testing"

func TestConservativePathsAndScopes(t *testing.T) {
	for _, p := range []string{"/", "/v1/items", "/v1/items/", "/a:@!$&'()*+,;=-._~"} {
		if !Path(p) {
			t.Errorf("valid path rejected %q", p)
		}
	}
	for _, p := range []string{"", "//x", "/a//b", "/a/../b", "/./a", "/%2f", "/a\\b", "/a b", "/ü", "/a?b", "/a#b", "/a{b}", "https://other.invalid/a"} {
		if Path(p) {
			t.Errorf("unsafe path accepted %q", p)
		}
	}
	p := Permission{Method: "GET,POST", Path: "/items", Kind: "subtree"}
	for _, v := range []struct {
		path string
		want bool
	}{{"/items", true}, {"/items/", true}, {"/items/a", true}, {"/items-other", false}, {"/item", false}} {
		if Match(p, "POST", v.path) != v.want {
			t.Errorf("boundary %s", v.path)
		}
	}
	if Match(p, "DELETE", "/items") {
		t.Fatal("method widened")
	}
	if !Overlap(p, Permission{Method: "POST", Path: "/items/a", Kind: "exact"}) || Overlap(p, Permission{Method: "DELETE", Path: "/items", Kind: "exact"}) {
		t.Fatal("overlap mismatch")
	}
	if Match(Permission{Method: "GET", Path: "/items", Kind: "exact"}, "GET", "/items/") {
		t.Fatal("exact trailing slash collapsed")
	}
}
func TestFixedDestination(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#fragment", "https://example.com/a/../b", "https://example.com/%61"} {
		if _, e := Base(u); e == nil {
			t.Errorf("unsafe base accepted %s", u)
		}
	}
	got, e := Target("https://upstream.invalid/api", "/v1/items", "a=%2f&b=two&b=three")
	if e != nil || got != "https://upstream.invalid/api/v1/items?a=%2f&b=two&b=three" {
		t.Fatalf("target changed: %s %v", got, e)
	}
}

func TestExplicitCustomMethods(t *testing.T) {
	if !Method("PROPFIND") || !Method("REPORT") {
		t.Fatal("general HTTP methods rejected")
	}
	for _, m := range []string{"CONNECT", "connect", "TRACE", "*", "GET POST", "GET\r\nX"} {
		if Method(m) {
			t.Fatalf("unsafe method %q accepted", m)
		}
	}
}
