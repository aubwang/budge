package server

import (
	"budge/internal/access"
	"budge/internal/store"
	"budge/internal/upstream"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"budge/internal/client"
	"budge/internal/requests"
)

func submitFixture(t *testing.T, h *harness, id client.Identity, key string) string {
	t.Helper()
	request, e := h.s.Submit(id.DeviceID, requests.Submission{Service: "mock", Method: "POST", Path: "/write", Body: "synthetic-write", IdempotencyKey: key})
	if e != nil {
		t.Fatal(e)
	}
	return request
}
func TestSlice4ConcurrentDecisionAndClaims(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	request := submitFixture(t, h, id, "race-key")
	out, _ := h.s.RequestStatus(id.DeviceID, request)
	var owner string
	h.db.DB.QueryRow("SELECT id FROM owners").Scan(&owner)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.s.Decide(owner, request, out.Digest, "approve")
			h.s.dispatch(context.Background(), request)
		}()
	}
	wg.Wait()
	h.waitStatus(id, request, "completed")
	if h.hits.Load() != 1 {
		t.Fatalf("duplicate dispatch: %d", h.hits.Load())
	}
}
func TestSlice4ConnectionLostAfterReceipt(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		conn.Close()
	})
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	request := submitFixture(t, h, id, "lost-after-receipt")
	h.s.dispatch(context.Background(), request)
	out := h.waitStatus(id, request, "outcome_unknown")
	if out.NextAction == "" {
		t.Fatal("uncertain outcome lacks guidance")
	}
	for range 5 {
		h.s.dispatch(context.Background(), request)
		h.s.RequestStatus(id.DeviceID, request)
	}
	if e := h.s.recoverDispatches(); e != nil {
		t.Fatal(e)
	}
	h.s.dispatch(context.Background(), request)
	if h.hits.Load() != 1 {
		t.Fatalf("transport or restart replayed: %d", h.hits.Load())
	}
}
func TestSlice4CrashRecoveryNeverResends(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	request := submitFixture(t, h, id, "crash-window")
	if _, e := h.db.DB.Exec("UPDATE requests SET status='dispatching' WHERE id=?", request); e != nil {
		t.Fatal(e)
	}
	if e := h.s.recoverDispatches(); e != nil {
		t.Fatal(e)
	}
	h.s.dispatch(context.Background(), request)
	out := h.waitStatus(id, request, "outcome_unknown")
	if !strings.Contains(out.Reason, "restarted") || h.hits.Load() != 0 {
		t.Fatal("restarted dispatch was replayed")
	}
}
func TestSlice4InvalidationPreventsClaims(t *testing.T) {
	for _, action := range []string{"/revoke-device", "/revoke-permission", "/service-revise", "/disable-service", "expire"} {
		t.Run(action, func(t *testing.T) {
			h := newHarness(t, nil)
			h.addService()
			id := h.enroll()
			h.approvalScope(id)
			pending := submitFixture(t, h, id, "pending")
			queued := submitFixture(t, h, id, "queued")
			out, _ := h.s.RequestStatus(id.DeviceID, queued)
			h.post("/decision", url.Values{"id": {queued}, "digest": {out.Digest}, "decision": {"approve"}}, 200)
			v := url.Values{"id": {id.DeviceID}}
			switch action {
			case "/revoke-permission":
				var p string
				h.db.DB.QueryRow("SELECT permission_id FROM requests WHERE id=?", queued).Scan(&p)
				v.Set("id", p)
			case "/service-revise":
				v = url.Values{"id": {"mock"}, "label": {"Rotated account"}, "base_url": {h.up.URL}, "auth": {"bearer"}, "credential": {"synthetic-rotated-credential"}}
			case "/disable-service":
				v.Set("id", "mock")
			}
			if action == "expire" {
				h.db.DB.Exec("UPDATE requests SET expires=?", time.Now().Add(-time.Second).Unix())
				h.s.maintenance()
			} else {
				h.post(action, v, 200)
			}
			h.s.dispatch(context.Background(), queued)
			for _, request := range []string{pending, queued} {
				out, e := h.s.RequestStatus("", request)
				if e != nil || out.Status != "cancelled" && out.Status != "expired" {
					t.Fatalf("invalidation failed %+v %v", out, e)
				}
			}
			if h.hits.Load() != 0 {
				t.Fatal("invalidated request dispatched")
			}
		})
	}
}
func TestSlice4SnapshotCannotReuseApproval(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	request := submitFixture(t, h, id, "immutable")
	out, _ := h.s.RequestStatus(id.DeviceID, request)
	h.post("/decision", url.Values{"id": {request}, "digest": {out.Digest}, "decision": {"approve"}}, 200)
	tx, _ := h.db.DB.Begin()
	snap, e := h.s.snapshot(tx, request)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	snap.Body = "changed-after-approval"
	b, _ := json.Marshal(snap)
	if _, e = h.db.DB.Exec("UPDATE requests SET snapshot=?,snapshot_digest=? WHERE id=?", h.db.Encrypt("request:"+request, b), requests.Digest(b), request); e != nil {
		t.Fatal(e)
	}
	h.s.dispatch(context.Background(), request)
	h.waitStatus(id, request, "failed")
	if h.hits.Load() != 0 {
		t.Fatal("changed snapshot reused approval")
	}
}
func TestSlice4ResultsAndRetention(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(503)
		io.WriteString(w, strings.Repeat("x", (1<<20)+1))
	})
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	in := requests.Submission{Service: "mock", Method: "POST", Path: "/write", Body: "synthetic-write", IdempotencyKey: "retention-key"}
	request, e := h.s.Submit(id.DeviceID, in)
	if e != nil {
		t.Fatal(e)
	}
	h.s.dispatch(context.Background(), request)
	out := h.waitStatus(id, request, "completed")
	if out.Result.HTTPStatus != 503 || !out.Result.Truncated || len(out.Result.Body) != 1<<20 {
		t.Fatal("bounded provider result not represented honestly")
	}
	h.db.DB.Exec("UPDATE requests SET finished=? WHERE id=?", time.Now().Add(-25*time.Hour).Unix(), request)
	h.s.maintenance()
	out, e = h.s.RequestStatus(id.DeviceID, request)
	if e != nil || !out.PayloadPurged || out.Result != nil {
		t.Fatal("retention failed")
	}
	dup, e := h.s.Submit(id.DeviceID, in)
	if e != nil || dup != request {
		t.Fatal("purged key reused as new request")
	}
	h.s.dispatch(context.Background(), request)
	if h.hits.Load() != 1 {
		t.Fatal("purge caused retry")
	}
}
func TestSlice4CertificateRenewal(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	block, _ := pem.Decode(id.Certificate)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotAfter = time.Now().Add(6 * 24 * time.Hour)
	der, e := x509.CreateCertificate(rand.Reader, leaf, h.s.root, leaf.PublicKey, h.s.rootKey)
	if e != nil {
		t.Fatal(e)
	}
	id.Certificate = certPEM(der)
	path := filepath.Join(h.dir, "device.identity")
	pass := "synthetic-device-passphrase"
	if e = client.Save(path, pass, id); e != nil {
		t.Fatal(e)
	}
	tr, e := client.Transport(id)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.CloseIdleConnections()
	renewal, e := client.NewRenewal(id, tr)
	if e != nil {
		t.Fatal(e)
	}
	if e = renewal.Refresh(context.Background(), path, pass); e != nil {
		t.Fatal(e)
	}
	next, e := client.Load(path, pass)
	if e != nil || next.DeviceID != id.DeviceID {
		t.Fatal("renewal changed identity")
	}
	cert, e := tls.X509KeyPair(next.Certificate, next.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	if time.Until(cert.Leaf.NotAfter) < 29*24*time.Hour {
		t.Fatal("certificate not extended")
	}
	c := &http.Client{Transport: tr}
	res, e := c.Post(id.URL+"/s/mock/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatal("renewal lost existing scope")
	}
	h.post("/revoke-device", url.Values{"id": {id.DeviceID}}, 200)
	res, e = c.Post(id.URL+"/s/mock/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("renewal bypassed revocation")
	}
}

func TestCrashDispatchHelper(t *testing.T) {
	if os.Getenv("BUDGE_CRASH_HELPER") != "1" {
		return
	}
	db, e := store.Open(os.Getenv("BUDGE_CRASH_DB"), fixtureUnlock)
	if e != nil {
		os.Exit(2)
	}
	defer db.Close()
	s, e := New(db, os.Getenv("BUDGE_CRASH_URL"), "127.0.0.1:8080", "")
	if e != nil {
		os.Exit(3)
	}
	root, e := base64.StdEncoding.DecodeString(os.Getenv("BUDGE_MOCK_ROOT"))
	if e != nil {
		os.Exit(4)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root)
	s.transport = func(access.Service) *http.Transport {
		return &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	s.dispatch(context.Background(), os.Getenv("BUDGE_CRASH_REQUEST"))
	os.Exit(0)
}
func TestSlice4RealProcessCrashAfterTransmission(t *testing.T) {
	received := make(chan struct{}, 1)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		received <- struct{}{}
		<-r.Context().Done()
	})
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	request := submitFixture(t, h, id, "process-crash")
	dbPath := filepath.Join(h.dir, "budge.db")
	serverURL := h.s.ca.URL
	root := certPEM(h.up.Certificate().Raw)
	h.db.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashDispatchHelper$")
	cmd.Env = []string{"BUDGE_CRASH_HELPER=1", "BUDGE_CRASH_DB=" + dbPath, "BUDGE_CRASH_URL=" + serverURL, "BUDGE_CRASH_REQUEST=" + request, "BUDGE_MOCK_ROOT=" + base64.StdEncoding.EncodeToString(root)}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("child did not transmit")
	}
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	cmd.Wait()
	db, e := store.Open(dbPath, fixtureUnlock)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s, e := New(db, serverURL, h.s.OwnerHost, "")
	if e != nil {
		t.Fatal(e)
	}
	s.transport = h.s.transport
	out, e := s.RequestStatus(id.DeviceID, request)
	if e != nil || out.Status != "outcome_unknown" {
		t.Fatalf("crash not recovered honestly: %+v %v", out, e)
	}
	for range 3 {
		s.dispatch(context.Background(), request)
	}
	if h.hits.Load() != 1 {
		t.Fatalf("crashed request resent: %d", h.hits.Load())
	}
}
func TestSlice4ExpiredCertificatesOnOpenConnection(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	block, _ := pem.Decode(id.Certificate)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	leaf.NotAfter = time.Now().Add(2 * time.Second)
	der, e := x509.CreateCertificate(rand.Reader, leaf, h.s.root, leaf.PublicKey, h.s.rootKey)
	if e != nil {
		t.Fatal(e)
	}
	id.Certificate = certPEM(der)
	tr, e := client.Transport(id)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}
	res, e := c.Post(id.URL+"/s/mock/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatal("valid short-lived cert rejected")
	}
	time.Sleep(time.Until(leaf.NotAfter) + 50*time.Millisecond)
	res, e = c.Post(id.URL+"/s/mock/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 || h.hits.Load() != 1 {
		t.Fatal("expired certificate authorized on existing TLS connection")
	}
}
func TestSlice4PendingLimitAndDedupAfterRevision(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	for i := 0; i < 20; i++ {
		submitFixture(t, h, id, fmt.Sprintf("pending-%d", i))
	}
	in := requests.Submission{Service: "mock", Method: "POST", Path: "/write", Body: "synthetic-write", IdempotencyKey: "overflow"}
	if _, e := h.s.Submit(id.DeviceID, in); e == nil || e.Error() != "pending_limit" {
		t.Fatal("pending limit not enforced")
	}
	in.IdempotencyKey = "pending-0"
	old, e := h.s.Submit(id.DeviceID, in)
	if e != nil {
		t.Fatal(e)
	}
	h.post("/service-revise", url.Values{"id": {"mock"}, "label": {"Replacement"}, "base_url": {h.up.URL}, "auth": {"bearer"}, "credential": {"synthetic-new-credential"}}, 200)
	dup, e := h.s.Submit(id.DeviceID, in)
	if e != nil || dup != old {
		t.Fatal("revision changed submission deduplication")
	}
	out, e := h.s.RequestStatus(id.DeviceID, dup)
	if e != nil || out.Status != "cancelled" {
		t.Fatal("obsolete duplicate acquired new authority")
	}
}
func TestSlice4ServerLeafRenewalAndDestinationBlock(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.grant(id, "/write")
	oldRoot := string(h.s.ca.Root)
	block, _ := pem.Decode(h.s.ca.Leaf)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	leaf.NotAfter = time.Now().Add(time.Hour)
	der, e := x509.CreateCertificate(rand.Reader, leaf, h.s.root, leaf.PublicKey, h.s.rootKey)
	if e != nil {
		t.Fatal(e)
	}
	h.s.ca.Leaf = certPEM(der)
	cfg, e := h.s.TLSConfig()
	if e != nil {
		t.Fatal(e)
	}
	if string(h.s.ca.Root) != oldRoot || time.Until(cfg.Certificates[0].Leaf.NotAfter) < 29*24*time.Hour {
		t.Fatal("server leaf renewal changed root or failed")
	}
	h.s.transport = upstream.Transport
	tr, e := client.Transport(id)
	if e != nil {
		t.Fatal(e)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}
	res, e := c.Post(id.URL+"/s/mock/write", "text/plain", strings.NewReader("x"))
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 502 || h.hits.Load() != 0 {
		t.Fatal("production transport allowed loopback upstream")
	}
}
func TestSlice4RestoredRecoveryInvalidatesAccess(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	request := submitFixture(t, h, id, "restore-pending")
	if e := h.s.RecoverRestored(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.s.Submit(id.DeviceID, requests.Submission{Service: "mock", Method: "POST", Path: "/write", IdempotencyKey: "after-restore"}); e == nil {
		t.Fatal("restored device stayed authorized")
	}
	out, e := h.s.RequestStatus("", request)
	if e != nil || out.Status != "cancelled" {
		t.Fatal("restored pending request survived")
	}
	var n int
	if e = h.db.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&n); e != nil || n != 0 {
		t.Fatal("restored sessions survived")
	}
}
func TestSlice4GlobalLimitAndAuditExclusion(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: synthetic\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	h.addService()
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	for i := 0; i < 9; i++ {
		id := h.enroll()
		h.grant(id, "/global")
		conn := h.connector(id)
		count := 4
		if i == 8 {
			count = 1
		}
		for range count {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			r, _ := http.NewRequestWithContext(ctx, "POST", conn.URL+"/s/mock/global?synthetic-sensitive-query", strings.NewReader("synthetic-sensitive-body"))
			res, e := conn.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			if i < 8 && res.StatusCode != 200 {
				t.Fatalf("unexpected early limit %d", res.StatusCode)
			}
			if i == 8 && res.StatusCode != 429 {
				t.Fatalf("global limit not enforced: %d", res.StatusCode)
			}
		}
	}
	if h.hits.Load() != 32 {
		t.Fatalf("global count %d", h.hits.Load())
	}
	for _, cancel := range cancels {
		cancel()
	}
	rows, e := h.db.DB.Query("SELECT kind,entity_id FROM audit")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, entity string
		rows.Scan(&kind, &entity)
		for _, forbidden := range []string{fixtureCredential, "synthetic-sensitive-body", "synthetic-sensitive-query", "/global"} {
			if strings.Contains(kind+entity, forbidden) {
				t.Fatal("sensitive material in audit")
			}
		}
	}
}
