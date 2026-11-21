package httpx

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
)

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example.com/v1/cves?apiKey=s3cret&page=2": "https://api.example.com/v1/cves?apiKey=xxxxx&page=xxxxx",
		"https://user:s3cret@pg.example.com:9091/metrics":      "https://user:xxxxx@pg.example.com:9091/metrics",
		"https://s3cret@github.com/org/repo":                   "https://xxxxx@github.com/org/repo",
		"https://example.com/feed.xml#token=s3cret":            "https://example.com/feed.xml",
		"https://example.com/feed.xml?flag":                    "https://example.com/feed.xml?flag",
		"https://example.com/plain":                            "https://example.com/plain",
		"http://[::1%zz/x?k=s3cret":                            "<invalid URL>",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactText(t *testing.T) {
	in := `Get "https://u:s3cret@h.example/x?token=s3cret": dial tcp: refused; parse https://h.example/feed?key=s3cret: EOF`
	got := RedactText(in)
	if strings.Contains(got, "s3cret") {
		t.Fatalf("secret left: %s", got)
	}
	want := `Get "https://u:xxxxx@h.example/x?token=xxxxx": dial tcp: refused; parse https://h.example/feed?key=xxxxx: EOF`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if s := "no url here"; RedactText(s) != s {
		t.Fatal("text without URLs must stay")
	}
}

func TestRedactError(t *testing.T) {
	base := context.DeadlineExceeded
	err := RedactError(errors.Join(errors.New("GET https://h.example/?apiKey=s3cret"), base))
	if strings.Contains(err.Error(), "s3cret") || !errors.Is(err, base) {
		t.Fatalf("got %v (is deadline: %v)", err, errors.Is(err, base))
	}
	if RedactError(nil) != nil || RedactError(base) != base { //nolint:errorlint // the same error, not wrapped
		t.Fatal("errors without URLs must pass through")
	}
}

// Transport errors, StatusError and the retry log must not carry the query
// token or the password.
func TestNoCredentialsInErrorsAndLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(config.HTTP{Timeout: config.Duration(5 * time.Second), Retries: 2, RetryBackoff: config.Duration(time.Millisecond)}, "t", logger)

	withCreds := strings.Replace(srv.URL, "://", "://user:pw-s3cret@", 1) + "/x?token=q-s3cret#frag-s3cret"
	var out any
	_, err := c.GetJSON(context.Background(), withCreds, nil, &out)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("want StatusError, got %v", err)
	}

	// A refused connection: the transport error quotes the URL.
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := strings.Replace(closed.URL, "://", "://user:pw-s3cret@", 1) + "/x?token=q-s3cret"
	closed.Close()
	_, err2 := c.GetJSON(context.Background(), closedURL, nil, &out)
	if err2 == nil {
		t.Fatal("want a connection error")
	}

	for name, s := range map[string]string{"status error": err.Error(), "transport error": err2.Error(), "logs": logs.String()} {
		if strings.Contains(s, "s3cret") {
			t.Errorf("%s leaks a credential: %s", name, s)
		}
	}
	if !strings.Contains(logs.String(), "token=xxxxx") {
		t.Errorf("retry log should name the redacted URL: %s", logs.String())
	}
}
