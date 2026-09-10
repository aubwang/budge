package server

import (
	"budge/internal/requests"
	"budge/web"
	"html/template"
	"net/http"
	"strconv"
)

var reviewPage = template.Must(template.New("review.html").ParseFS(web.Files, "review.html"))

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
		CSRF       string
		BodyQuoted string
		Status     requests.Status
		Snapshot   requests.Snapshot
	}{csrf, strconv.QuoteToASCII(snap.Body), status, snap})
}
