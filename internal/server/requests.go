package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"budge/internal/access"
	"budge/internal/requests"
	"budge/internal/store"
	"budge/internal/upstream"
)

func (s *Server) submit(w http.ResponseWriter, r *http.Request, device string) {
	if !s.throttle("submit:"+device, 30) {
		Error(w, 429, "throttled")
		return
	}
	var in requests.Submission
	if decode(w, r, &in, 512<<10) != nil {
		Error(w, 400, "invalid_submission")
		return
	}
	var e error
	in, e = requests.Normalize(in)
	if e != nil {
		Error(w, 400, e.Error())
		return
	}
	id, e := s.Submit(device, in)
	if e != nil {
		status := 400
		if e.Error() == "idempotency_conflict" {
			status = 409
		}
		if e.Error() == "permission_denied" {
			status = 403
		}
		if e.Error() == "pending_limit" {
			status = 429
		}
		Error(w, status, e.Error())
		return
	}
	out, e := s.RequestStatus(device, id)
	if e != nil {
		Error(w, 503, "storage_unavailable")
		return
	}
	JSON(w, out)
}
func (s *Server) Submit(device string, in requests.Submission) (string, error) {
	normalized, e := requests.Normalize(in)
	if e != nil {
		return "", e
	}
	in = normalized
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return "", errors.New("storage_unavailable")
	}
	defer tx.Rollback()
	if !access.ActiveDevice(tx, device) {
		return "", errors.New("permission_denied")
	}
	comparison := requests.SubmissionDigest(in)
	var id, digest string
	e = tx.QueryRow("SELECT id,submission_digest FROM requests WHERE device_id=? AND key_hash=?", device, store.Hash(in.IdempotencyKey)).Scan(&id, &digest)
	if e == nil {
		if comparison != digest {
			return "", errors.New("idempotency_conflict")
		}
		return id, nil
	}
	if e != sql.ErrNoRows {
		return "", errors.New("storage_unavailable")
	}
	svc, p, e := access.Authorize(tx, device, in.Service, in.Method, in.Path)
	if e != nil {
		return "", errors.New("permission_denied")
	}
	headers, e := requests.ApplicationHeaders(in, svc)
	if e != nil {
		return "", e
	}
	target, e := access.Target(svc.BaseURL, in.Path, in.Query)
	if e != nil {
		return "", errors.New("invalid_target")
	}
	state := "queued"
	expiry := time.Now().Add(time.Minute).Unix()
	if p.Mode == "approval_required" {
		state = "pending_approval"
		expiry = time.Now().Add(10 * time.Minute).Unix()
		var n int
		if e = tx.QueryRow("SELECT count(*) FROM requests WHERE device_id=? AND status='pending_approval' AND expires>?", device, time.Now().Unix()).Scan(&n); e != nil {
			return "", errors.New("storage_unavailable")
		}
		if n >= 20 {
			return "", errors.New("pending_limit")
		}
	}
	snap := requests.Snapshot{Version: 1, DeviceID: device, ServiceID: svc.ID, ServiceLabel: svc.Label, Revision: svc.Revision, PermissionID: p.ID, CredentialRef: "service:" + svc.ID + ":" + itoa(svc.Revision), URL: target, Method: in.Method, Path: in.Path, Headers: headers, Body: in.Body, Expires: expiry, PrivateCIDR: svc.PrivateCIDR}
	b, e := json.Marshal(snap)
	if e != nil {
		return "", errors.New("invalid_snapshot")
	}
	id = store.ID("req_")
	_, e = tx.Exec("INSERT INTO requests(id,device_id,service_id,revision,permission_id,key_hash,submission_digest,snapshot_digest,snapshot,status,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?)", id, device, svc.ID, svc.Revision, p.ID, store.Hash(in.IdempotencyKey), comparison, requests.Digest(b), s.Store.Encrypt("request:"+id, b), state, expiry)
	if e != nil {
		return "", errors.New("storage_unavailable")
	}
	if e = store.Audit(tx, "", device, "request_"+state, id); e != nil {
		return "", errors.New("storage_unavailable")
	}
	if e = tx.Commit(); e != nil {
		return "", errors.New("storage_unavailable")
	}
	return id, nil
}
func (s *Server) RequestStatus(device, id string) (requests.Status, error) {
	var out requests.Status
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if device != "" && !access.ActiveDevice(tx, device) {
		return out, errors.New("request_not_found")
	}
	var expires int64
	var result, snapshot []byte
	var origin string
	e = tx.QueryRow("SELECT id,device_id,status,expires,snapshot_digest,reason,result,snapshot FROM requests WHERE id=?", id).Scan(&out.RequestID, &origin, &out.Status, &expires, &out.Digest, &out.Reason, &result, &snapshot)
	if e != nil || (device != "" && origin != device) {
		return requests.Status{}, errors.New("request_not_found")
	}
	out.ExpiresAt = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	out.PayloadPurged = len(snapshot) == 0
	if len(result) > 0 {
		b, e := s.Store.Decrypt("result:"+id, result)
		if e != nil {
			return out, errors.New("result_unavailable")
		}
		out.Result = &requests.Result{}
		if e = json.Unmarshal(b, out.Result); e != nil {
			return out, e
		}
	}
	switch out.Status {
	case "pending_approval", "queued", "dispatching":
		out.NextAction = "Call budge_request_status with this request_id. Do not resubmit with a new idempotency key."
		out.PollAfterMS = 3000
	case "outcome_unknown":
		out.NextAction = "The upstream may have performed this request. Check the provider before considering a new request. Budge will not resend it."
	}
	return out, nil
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, device string) {
	var in requests.StatusInput
	if decode(w, r, &in, 4096) != nil || in.WaitSeconds < 0 || in.WaitSeconds > 15 {
		Error(w, 400, "invalid_status_request")
		return
	}
	deadline := time.Now().Add(time.Duration(in.WaitSeconds) * time.Second)
	for {
		out, e := s.RequestStatus(device, in.RequestID)
		if e != nil {
			Error(w, 404, "request_not_found")
			return
		}
		if in.WaitSeconds == 0 || time.Now().After(deadline) || terminal(out.Status) {
			JSON(w, out)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func terminal(status string) bool {
	return status != "pending_approval" && status != "queued" && status != "dispatching"
}
func (s *Server) snapshot(tx *sql.Tx, id string) (requests.Snapshot, error) {
	var snap requests.Snapshot
	var b []byte
	var digest, device, service, permission string
	var revision int
	var expires int64
	e := tx.QueryRow("SELECT snapshot,snapshot_digest,device_id,service_id,permission_id,revision,expires FROM requests WHERE id=?", id).Scan(&b, &digest, &device, &service, &permission, &revision, &expires)
	if e != nil {
		return snap, e
	}
	b, e = s.Store.Decrypt("request:"+id, b)
	if e != nil || requests.Digest(b) != digest {
		return snap, errors.New("snapshot_integrity_failed")
	}
	if e = json.Unmarshal(b, &snap); e != nil {
		return snap, e
	}
	if snap.Version != 1 || snap.DeviceID != device || snap.ServiceID != service || snap.PermissionID != permission || snap.Revision != revision || snap.Expires != expires || snap.CredentialRef != "service:"+service+":"+itoa(revision) {
		return snap, errors.New("snapshot_integrity_failed")
	}
	return snap, nil
}
func (s *Server) validSnapshot(tx *sql.Tx, snap requests.Snapshot) (access.Service, error) {
	svc, p, e := access.Authorize(tx, snap.DeviceID, snap.ServiceID, snap.Method, snap.Path)
	if e != nil || svc.Revision != snap.Revision || p.ID != snap.PermissionID || snap.Expires <= time.Now().Unix() {
		return svc, errors.New("authorization_changed_or_expired")
	}
	u, e := url.Parse(snap.URL)
	if e != nil {
		return svc, e
	}
	target, e := access.Target(svc.BaseURL, snap.Path, u.RawQuery)
	if e != nil || target != snap.URL || snap.PrivateCIDR != svc.PrivateCIDR {
		return svc, errors.New("snapshot_integrity_failed")
	}
	return svc, nil
}
func (s *Server) Decide(owner, id, digest, decision string) error {
	if decision != "approve" && decision != "deny" {
		return errors.New("invalid_decision")
	}
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state, stored string
	e = tx.QueryRow("SELECT status,snapshot_digest FROM requests WHERE id=?", id).Scan(&state, &stored)
	if e != nil || digest != stored {
		return errors.New("request_digest_mismatch")
	}
	if state != "pending_approval" {
		return errors.New("request_not_pending")
	}
	snap, e := s.snapshot(tx, id)
	if e != nil {
		return e
	}
	if _, e = s.validSnapshot(tx, snap); e != nil {
		return e
	}
	next := "queued"
	var finished any
	if decision == "deny" {
		next = "denied"
		finished = time.Now().Unix()
	}
	_, e = tx.Exec("INSERT INTO approvals(request_id,decided_by_owner_id,digest,decision) VALUES(?,?,?,?)", id, owner, digest, decision)
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE requests SET status=?,finished=? WHERE id=? AND status='pending_approval'", next, finished, id); e != nil {
		return e
	}
	if e = store.Audit(tx, owner, snap.DeviceID, "request_"+next, id); e != nil {
		return e
	}
	return tx.Commit()
}

// RunWorker owns the lifecycle of every spawned dispatch. Shutdown cancels work
// and waits for its durable outcome before the database can be closed.
func (s *Server) RunWorker(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.maintenance()
		rows, e := s.Store.DB.Query("SELECT id,device_id FROM requests WHERE status='queued' ORDER BY created,id LIMIT 32")
		if e != nil {
			continue
		}
		var candidates [][2]string
		for rows.Next() {
			var c [2]string
			if rows.Scan(&c[0], &c[1]) == nil {
				candidates = append(candidates, c)
			}
		}
		rows.Close()
		for _, c := range candidates {
			if !s.acquire(c[1]) {
				continue
			}
			wg.Add(1)
			go func(id, device string) { defer wg.Done(); defer s.release(device); s.dispatch(ctx, id) }(c[0], c[1])
		}
	}
}
func (s *Server) dispatch(ctx context.Context, id string) {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return
	}
	defer tx.Rollback()
	var state string
	if tx.QueryRow("SELECT status FROM requests WHERE id=?", id).Scan(&state) != nil || state != "queued" {
		return
	}
	snap, e := s.snapshot(tx, id)
	if e != nil {
		s.finishTx(tx, id, "failed", "snapshot_integrity_failed", nil)
		return
	}
	svc, e := s.validSnapshot(tx, snap)
	if e != nil {
		s.finishTx(tx, id, "cancelled", "authorization_changed_or_expired", nil)
		return
	}
	if _, e = tx.Exec("UPDATE requests SET status='dispatching' WHERE id=? AND status='queued'", id); e != nil {
		return
	}
	if e = store.Audit(tx, "", snap.DeviceID, "request_dispatching", id); e != nil {
		return
	}
	if e = tx.Commit(); e != nil {
		return
	}
	secret, e := s.Store.Decrypt(snap.CredentialRef, svc.Credential)
	if e != nil {
		s.finish(id, "failed", "credential_unavailable", nil)
		return
	}
	tr := s.transport(svc)
	defer tr.CloseIdleConnections()
	res, e := upstream.Send(ctx, svc, snap.Method, snap.URL, snap.Headers, strings.NewReader(snap.Body), secret, tr)
	if e != nil {
		s.finish(id, "outcome_unknown", "connection_lost_check_provider", nil)
		return
	}
	defer res.Body.Close()
	result := &requests.Result{HTTPStatus: res.StatusCode, Headers: upstream.Headers(res.Header, svc.ResponseHeaders, svc.AuthHeader), Encoding: "utf-8"}
	b, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if len(b) > 1<<20 {
		b = b[:1<<20]
		result.Truncated = true
	}
	if e != nil {
		result.Incomplete = true
	}
	if utf8.Valid(b) {
		result.Body = string(b)
	} else {
		result.Body = base64.StdEncoding.EncodeToString(b)
		result.Encoding = "base64"
	}
	state = "completed"
	reason := ""
	if e != nil {
		state = "outcome_unknown"
		reason = "incomplete_response_check_provider"
	}
	s.finish(id, state, reason, result)
}
func (s *Server) finish(id, state, reason string, result *requests.Result) {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return
	}
	defer tx.Rollback()
	s.finishTx(tx, id, state, reason, result)
}
func (s *Server) finishTx(tx *sql.Tx, id, state, reason string, result *requests.Result) {
	var encrypted any
	if result != nil {
		b, e := json.Marshal(result)
		if e != nil {
			return
		}
		encrypted = s.Store.Encrypt("result:"+id, b)
	}
	if _, e := tx.Exec("UPDATE requests SET status=?,reason=?,result=?,finished=? WHERE id=?", state, reason, encrypted, time.Now().Unix(), id); e != nil {
		return
	}
	if store.Audit(tx, "", "", "request_"+state, id) != nil {
		return
	}
	_ = tx.Commit()
}
func (s *Server) maintenance() {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	rows, e := tx.Query("SELECT id FROM requests WHERE status IN ('pending_approval','queued') AND expires<=?", now)
	if e != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE requests SET status='expired',reason='deadline_elapsed',finished=? WHERE id=?", now, id); e != nil {
			return
		}
		if store.Audit(tx, "", "", "request_expired", id) != nil {
			return
		}
	}
	if _, e = tx.Exec("UPDATE requests SET snapshot=NULL,result=NULL WHERE finished IS NOT NULL AND finished<? AND status NOT IN ('pending_approval','queued','dispatching')", now-24*3600); e != nil {
		return
	}
	_, _ = tx.Exec("DELETE FROM sessions WHERE expires<=?", now)
	_ = tx.Commit()
}
func (s *Server) recoverDispatches() error {
	tx, e := s.Store.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.Query("SELECT id FROM requests WHERE status='dispatching'")
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE requests SET status='outcome_unknown',reason='server_restarted_during_dispatch_check_provider',finished=? WHERE id=?", time.Now().Unix(), id); e != nil {
			return e
		}
		if e = store.Audit(tx, "", "", "request_outcome_unknown", id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func cancelRequests(tx *sql.Tx, column, id, reason string) error {
	if column != "device_id" && column != "service_id" && column != "permission_id" {
		return errors.New("invalid cancellation scope")
	}
	rows, e := tx.Query("SELECT id FROM requests WHERE "+column+"=? AND status IN ('pending_approval','queued')", id)
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, e = tx.Exec("UPDATE requests SET status='cancelled',reason=?,finished=? WHERE id=?", reason, time.Now().Unix(), id); e != nil {
			return e
		}
		if e = store.Audit(tx, "", "", "request_cancelled", id); e != nil {
			return e
		}
	}
	return nil
}
