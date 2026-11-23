package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
)

func TestGetJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "vulnwatch/1.2.3" {
			t.Errorf("UA %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"a":1}`))
		case "/nvd-style":
			w.Header().Set("message", "Invalid apiKey.")
			w.WriteHeader(http.StatusNotFound)
		case "/big":
			w.Write([]byte(`{"a":1,"pad":"` + strings.Repeat("x", 200) + `"}`))
		case "/trailing":
			w.Write([]byte(`{"a":1} {"a":2}`))
		case "/limit":
			w.Write([]byte(`{"a":2}` + strings.Repeat(" ", 93))) // exactly 100 bytes
		case "/after-limit":
			w.Write([]byte(`{"a":3}` + strings.Repeat(" ", 200)))
		}
	}))
	defer srv.Close()
	c := New(config.HTTP{UserAgent: "vulnwatch/{{version}}", Timeout: config.Duration(5 * time.Second), MaxResponseBytes: 100}, "1.2.3", nil)
	var out struct{ A int }
	if _, err := c.GetJSON(context.Background(), srv.URL+"/ok", nil, &out); err != nil || out.A != 1 {
		t.Fatal(out, err)
	}
	_, err := c.GetJSON(context.Background(), srv.URL+"/nvd-style?apiKey=secret", nil, &out)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 404 || se.Message != "Invalid apiKey." {
		t.Fatalf("status error: %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("query string leaked into error")
	}
	if _, err := c.GetJSON(context.Background(), srv.URL+"/big", nil, &out); err == nil || !strings.Contains(err.Error(), "response exceeds 100 bytes") {
		t.Fatalf("size limit: %v", err)
	}
	if _, err := c.GetJSON(context.Background(), srv.URL+"/after-limit", nil, &out); err == nil || !strings.Contains(err.Error(), "response exceeds 100 bytes") {
		t.Fatalf("size limit after the JSON value: %v", err)
	}
	if _, err := c.GetJSON(context.Background(), srv.URL+"/limit", nil, &out); err != nil || out.A != 2 {
		t.Fatalf("a body of exactly the limit: %v %v", out, err)
	}
	if _, err := c.GetJSON(context.Background(), srv.URL+"/trailing", nil, &out); err == nil || !strings.Contains(err.Error(), "data after the JSON value") {
		t.Fatalf("trailing data: %v", err)
	}
	body, _, err := c.Do(mustGet(t, srv.URL+"/big"))
	if err == nil || body != nil || !strings.Contains(err.Error(), "response exceeds 100 bytes") {
		t.Fatalf("Do size limit: %v", err)
	}
	if body, _, err = c.Do(mustGet(t, srv.URL+"/limit")); err != nil || len(body) != 100 {
		t.Fatalf("Do: %d %v", len(body), err)
	}
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/file":
			w.Write([]byte(strings.Repeat("x", 300))) // above max_response_bytes
		case "/stall":
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(config.HTTP{Timeout: config.Duration(200 * time.Millisecond), MaxResponseBytes: 100}, "1", nil)
	ctx := context.Background()
	var b strings.Builder
	if n, err := c.Download(ctx, srv.URL+"/file", &b, 1000); err != nil || n != 300 || b.Len() != 300 {
		t.Fatalf("download: %d %v", n, err)
	}
	if _, err := c.Download(ctx, srv.URL+"/file", io.Discard, 299); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("limit: %v", err)
	}
	var se *StatusError
	if _, err := c.Download(ctx, srv.URL+"/missing", io.Discard, 1000); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("status: %v", err)
	}
	if _, err := c.Download(ctx, srv.URL+"/stall", io.Discard, 1000); err == nil || !strings.Contains(err.Error(), "no data for") {
		t.Fatalf("stall: %v", err)
	}
}

func TestRetries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(config.HTTP{Timeout: config.Duration(5 * time.Second), Retries: 3, RetryBackoff: config.Duration(time.Millisecond)}, "t", nil)
	var out map[string]any
	if _, err := c.GetJSON(context.Background(), srv.URL, nil, &out); err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestRateLimitRetries(t *testing.T) {
	tests := []struct {
		name      string
		status    int               // first answer; then 200
		header    map[string]string // on the first answer
		wantCalls int
		wantErr   bool
	}{
		{"403 rate limit, nothing left", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, 2, false},
		{"403 with Retry-After", http.StatusForbidden, map[string]string{"Retry-After": "0"}, 2, false},
		{"403 forbidden", http.StatusForbidden, nil, 1, true},
		{"429 short Retry-After", http.StatusTooManyRequests, map[string]string{"Retry-After": "0"}, 2, false},
		{"429 Retry-After beyond the cap", http.StatusTooManyRequests, map[string]string{"Retry-After": "3600"}, 1, true},
		{"403 reset beyond the cap", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)}, 1, true},
		{"503 Retry-After date beyond the cap", http.StatusServiceUnavailable, map[string]string{"Retry-After": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					for k, v := range tt.header {
						w.Header().Set(k, v)
					}
					w.WriteHeader(tt.status)
					return
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			c := New(config.HTTP{Timeout: config.Duration(5 * time.Second), Retries: 3, RetryBackoff: config.Duration(time.Millisecond)}, "t", nil)
			var out map[string]any
			_, err := c.GetJSON(context.Background(), srv.URL, nil, &out)
			var se *StatusError
			if (err != nil) != tt.wantErr || calls != tt.wantCalls || (err != nil && (!errors.As(err, &se) || se.Status != tt.status)) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestBackoffCapsServerWait(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"60"}}}
	if got := backoff(time.Millisecond, time.Second, 0, resp); got != time.Second {
		t.Fatalf("Retry-After must be capped: %v", got)
	}
	resp.Header.Set("Retry-After", "1")
	if got := backoff(time.Millisecond, 5*time.Second, 0, resp); got != time.Second {
		t.Fatalf("Retry-After must be honoured: %v", got)
	}
	if got := backoff(time.Millisecond, time.Second, 2, &http.Response{StatusCode: http.StatusBadGateway}); got != 4*time.Millisecond {
		t.Fatalf("exponential without a server hint: %v", got)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(20 * time.Millisecond)
	start := time.Now()
	for range 3 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Fatalf("too fast: %v", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewLimiter(time.Hour).Wait(ctx); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestTLSFloor(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	p := Plain(time.Second)
	p.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true // the test server's certificate is self-signed
	resp, err := p.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a TLS 1.1 server must be refused")
	}
}

func TestErrorText(t *testing.T) {
	cloudflare := "<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n<script>(function(){var x=1})();</script></body></html>"
	tests := []struct{ name, body, ctype, want string }{
		{"html page by type", cloudflare, "text/html", "503 Service Unavailable"},
		{"html page by body", cloudflare, "", "503 Service Unavailable"},
		{"title only", "<!DOCTYPE html><html><head><title>\n Bad  gateway </title><script>x()</script>", "", "Bad gateway"},
		{"html without heading", "<html><script>x()</script></html>", "text/html", ""},
		{"json", `{"message":"Invalid apiKey"}`, "application/json", `{"message":"Invalid apiKey"}`},
		{"long text", strings.Repeat("a", 299) + "é", "text/plain", strings.Repeat("a", 299) + "…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorText([]byte(tt.body), tt.ctype); got != tt.want {
				t.Errorf("errorText = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWithTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(config.HTTP{Timeout: config.Duration(100 * time.Millisecond)}, "1", nil)
	var v map[string]any
	if _, err := c.GetJSON(context.Background(), srv.URL, nil, &v); err == nil {
		t.Fatal("the short timeout must cut the slow answer")
	}
	if _, err := c.WithTimeout(2*time.Second).GetJSON(context.Background(), srv.URL, nil, &v); err != nil {
		t.Fatalf("longer timeout: %v", err)
	}
	if c.WithTimeout(0) != c {
		t.Fatal("zero keeps the client")
	}
}

// A failed POST must not be reported as a GET: the method comes from the
// request, and an error built without one still reads as GET.
func TestStatusErrorNamesTheMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "1", nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Do(req)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("want a StatusError, got %v", err)
	}
	if se.Method != http.MethodPost || !strings.HasPrefix(err.Error(), "POST ") {
		t.Errorf("error = %q, want it to start with POST", err)
	}
	zero := &StatusError{URL: "https://h.example", Status: 500}
	if !strings.HasPrefix(zero.Error(), "GET ") {
		t.Errorf("error without a method = %q, want the GET default", zero)
	}
}
