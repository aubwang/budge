package mcp

import (
	"budge/internal/requests"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net/http"
)

func New(c *http.Client) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "budge", Version: "0.1.0-dev"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "budge_services", Description: "List this device's available services and permission scopes, including whether approval is required."}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, map[string]any, error) {
		out, e := call(ctx, c, "GET", "/services", nil)
		return nil, out, e
	})
	sdk.AddTool(s, &sdk.Tool{Name: "budge_request", Description: "Submit a finite UTF-8 HTTP request. Requires a unique client-generated idempotency_key. Pending approval is a durable application state; poll with budge_request_status instead of resubmitting."}, func(ctx context.Context, _ *sdk.CallToolRequest, in requests.Submission) (*sdk.CallToolResult, map[string]any, error) {
		normalized, e := requests.Normalize(in)
		if e != nil {
			return nil, nil, e
		}
		out, e := call(ctx, c, "POST", "/request", normalized)
		return nil, out, e
	})
	sdk.AddTool(s, &sdk.Tool{Name: "budge_request_status", Description: "Retrieve your request's status/result. Optional wait_seconds is bounded to 15. Polling never dispatches a request."}, func(ctx context.Context, _ *sdk.CallToolRequest, in requests.StatusInput) (*sdk.CallToolResult, map[string]any, error) {
		if in.WaitSeconds < 0 || in.WaitSeconds > 15 {
			return nil, nil, errors.New("wait_seconds must be between 0 and 15")
		}
		out, e := call(ctx, c, "POST", "/status", in)
		return nil, out, e
	})
	return s
}
func call(ctx context.Context, c *http.Client, method, path string, in any) (map[string]any, error) {
	var b []byte
	if in != nil {
		var e error
		b, e = json.Marshal(in)
		if e != nil {
			return nil, e
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, "http://budge-socket"+path, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	res, e := c.Do(r)
	if e != nil {
		return nil, errors.New("connector unavailable")
	}
	defer res.Body.Close()
	var out map[string]any
	if e = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&out); e != nil {
		return nil, errors.New("invalid connector response")
	}
	if res.StatusCode != 200 {
		if detail, ok := out["error"].(map[string]any); ok {
			if code, ok := detail["code"].(string); ok {
				return nil, errors.New(code)
			}
		}
		return nil, errors.New("request rejected")
	}
	return out, nil
}
