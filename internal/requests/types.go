package requests

import (
	"budge/internal/access"
	"budge/internal/store"
	"budge/internal/upstream"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"
)

type Submission struct {
	Service        string            `json:"service"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          string            `json:"query,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	IdempotencyKey string            `json:"idempotency_key"`
}
type StatusInput struct {
	RequestID   string `json:"request_id"`
	WaitSeconds int    `json:"wait_seconds,omitempty"`
}
type Snapshot struct {
	Version       int         `json:"version"`
	DeviceID      string      `json:"device_id"`
	ServiceID     string      `json:"service_id"`
	ServiceLabel  string      `json:"service_label"`
	Revision      int         `json:"service_revision"`
	PermissionID  string      `json:"permission_id"`
	CredentialRef string      `json:"credential_ref"`
	URL           string      `json:"effective_url"`
	Method        string      `json:"method"`
	Path          string      `json:"path"`
	Headers       http.Header `json:"headers"`
	Body          string      `json:"body"`
	Expires       int64       `json:"expires"`
	PrivateCIDR   string      `json:"private_cidr,omitempty"`
}
type Result struct {
	HTTPStatus int         `json:"http_status"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
	Encoding   string      `json:"encoding"`
	Truncated  bool        `json:"result_truncated"`
	Incomplete bool        `json:"result_incomplete"`
}
type Status struct {
	RequestID     string  `json:"request_id"`
	Status        string  `json:"status"`
	ExpiresAt     string  `json:"expires_at"`
	Digest        string  `json:"digest,omitempty"`
	Reason        string  `json:"reason,omitempty"`
	NextAction    string  `json:"next_action,omitempty"`
	PollAfterMS   int     `json:"poll_after_ms,omitempty"`
	Result        *Result `json:"result,omitempty"`
	PayloadPurged bool    `json:"payload_purged,omitempty"`
}

func Normalize(in Submission) (Submission, error) {
	if !access.Slug.MatchString(in.Service) || !access.Method(in.Method) || !access.Path(in.Path) || !utf8.ValidString(in.Body) || len(in.Body) > 64<<10 || len(in.IdempotencyKey) < 1 || len(in.IdempotencyKey) > 128 {
		return in, errors.New("invalid_submission")
	}
	for _, c := range []byte(in.IdempotencyKey) {
		if c < 33 || c > 126 {
			return in, errors.New("invalid_idempotency_key")
		}
	}
	if _, e := access.Target("https://example.invalid", in.Path, in.Query); e != nil {
		return in, errors.New("invalid_query")
	}
	out := map[string]string{}
	size := 0
	for n, v := range in.Headers {
		if !upstream.HeaderName(n) || !upstream.HeaderValue(v) || upstream.Reserved(n) {
			return in, errors.New("invalid_header")
		}
		n = http.CanonicalHeaderKey(n)
		if _, ok := out[n]; ok {
			return in, errors.New("duplicate_header")
		}
		out[n] = v
		size += len(n) + len(v)
	}
	if size > 16<<10 {
		return in, errors.New("headers_too_large")
	}
	in.Headers = out
	return in, nil
}
func ApplicationHeaders(in Submission, s access.Service) (http.Header, error) {
	h := http.Header{}
	for n, v := range in.Headers {
		allowed := false
		for _, a := range s.RequestHeaders {
			if strings.EqualFold(n, a) {
				allowed = true
			}
		}
		if !allowed || strings.EqualFold(n, s.AuthHeader) {
			return nil, errors.New("header_not_allowed")
		}
		h.Set(n, v)
	}
	return h, nil
}
func Digest(b []byte) string { return "sha256-v1:" + store.Hash(string(b)) }
func SubmissionDigest(in Submission) string {
	in.IdempotencyKey = ""
	b, _ := json.Marshal(in)
	return Digest(b)
}
