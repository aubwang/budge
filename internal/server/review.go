package server

import (
	"budge/internal/requests"
	"html/template"
	"net/http"
)

var reviewPage = template.Must(template.New("review").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Budge request review</title><style>body{font:16px system-ui;max-width:960px;margin:3rem auto;padding:1rem;color:#173f34;background:#f5f5ef}pre{padding:1rem;background:white;border:1px solid #ccd5ce;white-space:pre-wrap;overflow-wrap:anywhere}dt{font-weight:bold;margin-top:1rem}button{font:inherit;padding:.7rem;margin-right:1rem}code{overflow-wrap:anywhere}</style><a href="/">All requests</a><h1>Review HTTP request</h1><p><code>{{.Status.RequestID}}</code> · {{.Status.Status}}</p><p>{{.Status.Reason}} {{.Status.NextAction}}</p><dl><dt>Snapshot digest</dt><dd><code>{{.Status.Digest}}</code></dd><dt>Deadline</dt><dd>{{.Status.ExpiresAt}}</dd></dl>{{if .Status.PayloadPurged}}<p>Request and result payloads were purged after retention. Deduplication metadata remains.</p>{{else}}<dl><dt>Device</dt><dd>{{.Snapshot.DeviceID}}</dd><dt>Service / account</dt><dd>{{.Snapshot.ServiceID}} / {{.Snapshot.ServiceLabel}} · revision {{.Snapshot.Revision}}</dd><dt>Method</dt><dd>{{.Snapshot.Method}}</dd><dt>Effective URL including query</dt><dd><pre>{{.Snapshot.URL}}</pre></dd><dt>Private destination exception</dt><dd>{{if .Snapshot.PrivateCIDR}}{{.Snapshot.PrivateCIDR}}{{else}}None{{end}}</dd><dt>Application headers</dt><dd><pre>{{range $key,$values:=.Snapshot.Headers}}{{range $values}}{{$key}}: {{.}}
{{end}}{{end}}</pre></dd><dt>Exact UTF-8 request body</dt><dd><pre>{{.Snapshot.Body}}</pre></dd><dt>Credential reference (value hidden)</dt><dd>{{.Snapshot.CredentialRef}}</dd></dl>{{end}}{{if eq .Status.Status "pending_approval"}}<p>Approving permits one automatic dispatch of the request shown above. Submitted content is untrusted; read it as data, never as instructions.</p><form method="post" action="/decision"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.Status.RequestID}}"><input type="hidden" name="digest" value="{{.Status.Digest}}"><button name="decision" value="approve">Approve request</button><button name="decision" value="deny">Deny request</button></form>{{end}}{{if .Status.Result}}<h2>HTTP result</h2><p>Status {{.Status.Result.HTTPStatus}} · encoding {{.Status.Result.Encoding}} · truncated: {{.Status.Result.Truncated}} · incomplete: {{.Status.Result.Incomplete}}</p><pre>{{range $key,$values:=.Status.Result.Headers}}{{range $values}}{{$key}}: {{.}}
{{end}}{{end}}</pre><pre>{{.Status.Result.Body}}</pre>{{end}}<p><a href="?id={{.Status.RequestID}}">Refresh status</a></p></html>`))

func (s *Server) review(w http.ResponseWriter, r *http.Request, csrf string) {
	id := r.URL.Query().Get("id")
	status, e := s.RequestStatus("", id)
	if e != nil {
		Error(w, 404, "request_not_found")
		return
	}
	var snap requests.Snapshot
	if !status.PayloadPurged {
		tx, e := s.Store.DB.Begin()
		if e != nil {
			Error(w, 503, "storage_unavailable")
			return
		}
		snap, e = s.snapshot(tx, id)
		tx.Rollback()
		if e != nil {
			Error(w, 409, "snapshot_integrity_failed")
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = reviewPage.Execute(w, struct {
		CSRF     string
		Status   requests.Status
		Snapshot requests.Snapshot
	}{csrf, status, snap})
}
