package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSlice2StreamingCancellationAndLimits(t *testing.T) {
	started := make(chan struct{}, 8)
	cancelled := make(chan struct{}, 8)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
	})
	h.addService()
	id := h.enroll()
	h.grant(id, "/stream")
	conn := h.connector(id)
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		req, _ := http.NewRequestWithContext(ctx, "POST", conn.URL+"/s/mock/stream", strings.NewReader("x"))
		res, e := conn.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		line := make(chan string, 1)
		go func() { v, _ := bufio.NewReader(res.Body).ReadString('\n'); line <- v }()
		select {
		case got := <-line:
			if got != "data: first\n" {
				t.Fatalf("unexpected SSE %q", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("first event buffered until upstream closed")
		}
		<-started
	}
	res, e := conn.Client().Post(conn.URL+"/s/mock/stream", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 429 {
		t.Fatalf("expected per-device limit, got %d", res.StatusCode)
	}
	for _, c := range cancels {
		c()
	}
	for range 4 {
		select {
		case <-cancelled:
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation did not reach upstream")
		}
	}
	res, e = conn.Client().Post(conn.URL+"/s/mock/stream", "text/plain", strings.NewReader(strings.Repeat("x", (8<<20)+1)))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Fatal("oversized body accepted")
	}
	if h.hits.Load() != 4 {
		t.Fatal("rejected request reached upstream")
	}
}
func TestSlice2ScopesRevisionsAndDirectApproval(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.post("/permission", url.Values{"device": {id.DeviceID}, "service": {"mock"}, "method": {"GET,POST"}, "path": {"/items"}, "path_kind": {"subtree"}}, 200)
	h.post("/permission", url.Values{"device": {id.DeviceID}, "service": {"mock"}, "method": {"POST"}, "path": {"/items/one"}, "mode": {"approval_required"}}, 400)
	conn := h.connector(id)
	for _, v := range []struct {
		path string
		want int
	}{{"/items", 201}, {"/items/one", 201}, {"/items-other", 403}, {"/items/%2e%2e/x", 400}, {"//items", 400}} {
		res, e := conn.Client().Post(conn.URL+"/s/mock"+v.path, "text/plain", strings.NewReader("x"))
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != v.want {
			t.Fatalf("path %s got %d", v.path, res.StatusCode)
		}
	}
	h.post("/permission", url.Values{"device": {id.DeviceID}, "service": {"mock"}, "method": {"POST"}, "path": {"/approval"}, "mode": {"approval_required"}}, 200)
	res, e := conn.Client().Post(conn.URL+"/s/mock/approval", "text/plain", nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 403 || !strings.Contains(string(b), "approval_required") {
		t.Fatal("approval route bypassed")
	}
	h.post("/service-revise", url.Values{"id": {"mock"}, "label": {"New synthetic account"}, "base_url": {h.up.URL + "/api"}, "auth": {"bearer"}, "credential": {fixtureCredential}}, 200)
	res, e = conn.Client().Post(conn.URL+"/s/mock/items", "text/plain", nil)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("obsolete permission authorized")
	}
	h.grant(id, "/items")
	res, e = conn.Client().Post(conn.URL+"/s/mock/items", "text/plain", nil)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatal("reissued permission failed")
	}
}
func TestSlice2RedirectAndHeaders(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-App") != "present" || r.Header.Get("X-Unknown") != "" {
			t.Error("application header policy mismatch")
		}
		w.Header().Set("Location", "https://unconfigured.invalid/steal")
		w.Header().Set("X-Response", "allowed")
		w.Header().Set("Authorization", "do-not-forward")
		w.WriteHeader(307)
	})
	h.post("/service", url.Values{"id": {"mock"}, "label": {"Synthetic"}, "base_url": {h.up.URL}, "auth": {"bearer"}, "credential": {fixtureCredential}, "request_headers": {"Accept, Content-Type, X-App"}, "response_headers": {"Content-Type, X-Response"}}, 200)
	id := h.enroll()
	h.grant(id, "/write")
	conn := h.connector(id)
	req, _ := http.NewRequest("POST", conn.URL+"/s/mock/write", nil)
	req.Header.Set("X-App", "present")
	req.Header.Set("X-Unknown", "absent")
	res, e := conn.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 307 || res.Header.Get("X-Response") != "allowed" || res.Header.Get("Authorization") != "" || h.hits.Load() != 1 {
		t.Fatal("redirect or response policy failed")
	}
	h.post("/service-revise", url.Values{"id": {"mock"}, "label": {"Synthetic"}, "base_url": {h.up.URL}, "auth": {"none"}, "request_headers": {"Authorization"}}, 400)
}
