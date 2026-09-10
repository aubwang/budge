package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in measurements use synthetic data and the same end-to-end harness.
// The process contains mock + server + connector: memory is combined Go heap,
// not a claim about an isolated production server's resident memory.
func TestMeasureMockGateway(t *testing.T) {
	if os.Getenv("BUDGE_MEASURE") != "1" {
		t.Skip("opt-in measurement")
	}
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Query().Get("long") == "1" {
			chunk := strings.Repeat("x", 32<<10)
			for i := 0; i < 2048; i++ {
				if _, e := io.WriteString(w, chunk); e != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			return
		}
		io.WriteString(w, "data: synthetic\n\n")
		w.(http.Flusher).Flush()
	})
	h.addService()
	id := h.enroll()
	h.grant(id, "/stream")
	conn := h.connector(id)
	call := func(c *http.Client, target string) (float64, error) {
		start := time.Now()
		req, _ := http.NewRequest("POST", target, strings.NewReader("synthetic"))
		req.Header.Set("Authorization", "Bearer "+fixtureCredential)
		res, e := c.Do(req)
		if e != nil {
			return 0, e
		}
		defer res.Body.Close()
		one := make([]byte, 1)
		if _, e = io.ReadFull(res.Body, one); e != nil {
			return 0, e
		}
		ms := float64(time.Since(start).Microseconds()) / 1000
		_, e = io.Copy(io.Discard, res.Body)
		if res.StatusCode != 200 {
			return 0, fmt.Errorf("status %d", res.StatusCode)
		}
		return ms, e
	}
	stats := func(c *http.Client, target string) (float64, float64) {
		samples := []float64{}
		for i := 0; i < 35; i++ {
			ms, e := call(c, target)
			if e != nil {
				t.Fatal(e)
			}
			if i >= 5 {
				samples = append(samples, ms)
			}
		}
		sort.Float64s(samples)
		return samples[len(samples)/2], samples[28]
	}
	direct := h.up.URL + "/api/stream"
	gateway := conn.URL + "/s/mock/stream"
	dp50, dp95 := stats(h.up.Client(), direct)
	gp50, gp95 := stats(conn.Client(), gateway)
	fmt.Printf("MEASURE Go=%s OS=%s arch=%s CPUs=%d samples=30 warmups=5\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("MEASURE first_byte_ms direct_p50=%.3f direct_p95=%.3f gateway_p50=%.3f gateway_p95=%.3f median_added=%.3f\n", dp50, dp95, gp50, gp95, gp50-dp50)
	throughput := func(c *http.Client, target string) float64 {
		var wg sync.WaitGroup
		start := time.Now()
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 10 {
					if _, e := call(c, target); e != nil {
						t.Error(e)
					}
				}
			}()
		}
		wg.Wait()
		return 40 / time.Since(start).Seconds()
	}
	fmt.Printf("MEASURE concurrency=4 requests=40 direct_rps=%.2f gateway_rps=%.2f\n", throughput(h.up.Client(), direct), throughput(conn.Client(), gateway))
	runtime.GC()
	var before, mid, after runtime.MemStats
	runtime.ReadMemStats(&before)
	req, _ := http.NewRequest("POST", gateway+"?long=1", strings.NewReader("synthetic"))
	res, e := conn.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	n, e := io.CopyN(io.Discard, res.Body, 32<<20)
	if e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	runtime.ReadMemStats(&mid)
	rest, e := io.Copy(io.Discard, res.Body)
	if e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fmt.Printf("MEASURE long_stream_bytes=%d combined_live_heap_bytes before=%d midpoint=%d after=%d\n", n+rest, before.HeapAlloc, mid.HeapAlloc, after.HeapAlloc)
}
