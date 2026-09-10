package client

import (
	"budge/internal/access"
	"encoding/json"
	"errors"
	"net"
)

// OpenCodeConfig emits only routing and a deliberately non-secret placeholder.
// Live provider compatibility must be recorded separately from mock verification.
func OpenCodeConfig(host, service string) ([]byte, error) {
	h, p, e := net.SplitHostPort(host)
	if e != nil || h != "127.0.0.1" || p == "" || !access.Slug.MatchString(service) {
		return nil, errors.New("invalid local service URL")
	}
	return json.MarshalIndent(map[string]any{"$schema": "https://opencode.ai/config.json", "provider": map[string]any{"openrouter": map[string]any{"options": map[string]any{"baseURL": "http://" + host + "/s/" + service + "/v1", "apiKey": "budge-local"}}}}, "", "  ")
}
