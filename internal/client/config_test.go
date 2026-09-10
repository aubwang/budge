package client

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGeneratedConfig(t *testing.T) {
	b, e := OpenCodeConfig("127.0.0.1:7777", "openrouter")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil || !strings.Contains(string(b), "http://127.0.0.1:7777/s/openrouter/v1") || !strings.Contains(string(b), "budge-local") {
		t.Fatal("invalid routing config")
	}
	if _, e = OpenCodeConfig("0.0.0.0:7777", "openrouter"); e == nil {
		t.Fatal("public connector accepted")
	}
}
