package server

import (
	"context"
	"encoding/json"
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
	budgemcp "budge/internal/mcp"
	"budge/internal/requests"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func (h *harness) worker() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.s.RunWorker(ctx) }()
	h.t.Cleanup(func() { cancel(); <-done })
}
func (h *harness) approvalScope(id client.Identity) {
	h.post("/permission", url.Values{"device": {id.DeviceID}, "service": {"mock"}, "method": {"POST"}, "path": {"/write"}, "mode": {"approval_required"}}, 200)
}
func (h *harness) waitStatus(id client.Identity, request, want string) requests.Status {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, e := h.s.RequestStatus(id.DeviceID, request)
		if e != nil {
			h.t.Fatal(e)
		}
		if out.Status == want {
			return out
		}
		if terminal(out.Status) {
			h.t.Fatalf("wanted %s got %+v", want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("request did not reach " + want)
	return requests.Status{}
}
func TestMCPStdioHelper(t *testing.T) {
	if os.Getenv("BUDGE_TEST_MCP_HELPER") != "1" {
		return
	}
	c, e := client.SocketClient(os.Getenv("BUDGE_TEST_SOCKET"))
	if e != nil {
		os.Exit(2)
	}
	if e = budgemcp.New(c).Run(context.Background(), &sdk.StdioTransport{}); e != nil {
		os.Exit(3)
	}
	os.Exit(0)
}
func (h *harness) mcp(id client.Identity) *sdk.ClientSession {
	h.t.Helper()
	path := filepath.Join(h.dir, id.DeviceID, "connect.sock")
	l, e := client.ListenSocket(path)
	if e != nil {
		h.t.Fatal(e)
	}
	handler, close, e := client.SocketHandler(id)
	if e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(close)
	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	h.t.Cleanup(func() { srv.Close(); l.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPStdioHelper$")
	cmd.Env = []string{"BUDGE_TEST_MCP_HELPER=1", "BUDGE_TEST_SOCKET=" + path}
	host := sdk.NewClient(&sdk.Implementation{Name: "budge-test-host", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h.t.Cleanup(cancel)
	session, e := host.Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(func() { session.Close() })
	return session
}
func tool(t *testing.T, s *sdk.ClientSession, name string, in any) map[string]any {
	t.Helper()
	res, e := s.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: in})
	if e != nil || res.IsError {
		t.Fatalf("tool %s failed: %v %v", name, e, res)
	}
	if len(res.Content) == 0 || res.StructuredContent == nil {
		t.Fatal("missing text or structured output")
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}
func TestSlice3MCPApprovalRoundTrip(t *testing.T) {
	body := "{\"action\":\"create fixture\",\"untrusted\":\"<script>alert(1)</script>\"}"
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	other := h.enroll()
	session := h.mcp(id)
	h.worker()
	scopes := tool(t, session, "budge_services", map[string]any{})
	if !strings.Contains(string(mustJSON(scopes)), "approval_required") {
		t.Fatal("missing approval scope")
	}
	otherSession := h.mcp(other)
	otherScopes := tool(t, otherSession, "budge_services", map[string]any{})
	if strings.Contains(string(mustJSON(otherScopes)), "mock") {
		t.Fatal("service scope leaked")
	}
	in := requests.Submission{Service: "mock", Method: "POST", Path: "/write", Query: "fixture=1", Body: body, IdempotencyKey: "fixture-write-one"}
	out := tool(t, session, "budge_request", in)
	idRequest := out["request_id"].(string)
	if out["status"] != "pending_approval" || h.hits.Load() != 0 {
		t.Fatal("dispatched before approval")
	}
	again := tool(t, session, "budge_request", in)
	if again["request_id"] != idRequest {
		t.Fatal("duplicate submission created request")
	}
	tool(t, session, "budge_request_status", requests.StatusInput{RequestID: idRequest})
	denied, e := otherSession.CallTool(context.Background(), &sdk.CallToolParams{Name: "budge_request_status", Arguments: requests.StatusInput{RequestID: idRequest}})
	if e == nil && !denied.IsError {
		t.Fatal("other device read request")
	}
	extra := map[string]any{"service": "mock", "method": "POST", "path": "/write", "idempotency_key": "extra-key", "unexpected": true}
	bad, e := session.CallTool(context.Background(), &sdk.CallToolParams{Name: "budge_request", Arguments: extra})
	if e == nil && !bad.IsError {
		t.Fatal("unknown MCP argument accepted")
	}
	res, e := h.browser.Get(h.owner.URL + "/request?id=" + idRequest)
	if e != nil {
		t.Fatal(e)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(page), "&lt;script&gt;") || strings.Contains(string(page), "<script>") || strings.Contains(string(page), fixtureCredential) || !strings.Contains(string(page), "fixture=1") {
		t.Fatal("review does not safely show exact request")
	}
	h.post("/decision", url.Values{"id": {idRequest}, "digest": {"wrong"}, "decision": {"approve"}}, 400)
	if h.hits.Load() != 0 {
		t.Fatal("wrong digest dispatched")
	}
	h.post("/decision", url.Values{"id": {idRequest}, "digest": {out["digest"].(string)}, "decision": {"approve"}}, 200)
	completed := h.waitStatus(id, idRequest, "completed")
	if completed.Result.HTTPStatus != 201 || completed.Result.Body != body || h.hits.Load() != 1 {
		t.Fatalf("unexpected result %+v hits %d", completed, h.hits.Load())
	}
	h.post("/decision", url.Values{"id": {idRequest}, "digest": {out["digest"].(string)}, "decision": {"approve"}}, 400)
	tool(t, session, "budge_request_status", requests.StatusInput{RequestID: idRequest})
	if h.hits.Load() != 1 {
		t.Fatal("duplicate decision or polling resent")
	}
	raw, _ := os.ReadFile(filepath.Join(h.dir, "budge.db-wal"))
	if strings.Contains(string(raw), body) || strings.Contains(string(raw), fixtureCredential) {
		t.Fatal("plaintext payload or credential persisted")
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestSlice3ConcurrentDedupAndDenial(t *testing.T) {
	h := newHarness(t, nil)
	h.addService()
	id := h.enroll()
	h.approvalScope(id)
	in := requests.Submission{Service: "mock", Method: "POST", Path: "/write", Body: "synthetic", IdempotencyKey: "same-key"}
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, e := h.s.Submit(id.DeviceID, in)
			if e != nil {
				t.Error(e)
				return
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	request := ""
	for id := range ids {
		if request != "" && request != id {
			t.Fatal("dedup race")
		}
		request = id
	}
	in.Body = "changed"
	if _, e := h.s.Submit(id.DeviceID, in); e == nil || e.Error() != "idempotency_conflict" {
		t.Fatal("changed data reused key")
	}
	status, e := h.s.RequestStatus(id.DeviceID, request)
	if e != nil {
		t.Fatal(e)
	}
	h.post("/decision", url.Values{"id": {request}, "digest": {status.Digest}, "decision": {"deny"}}, 200)
	h.worker()
	out := h.waitStatus(id, request, "denied")
	if out.Status != "denied" || h.hits.Load() != 0 {
		t.Fatal("denied write dispatched")
	}
}
