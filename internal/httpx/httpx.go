// Package httpx provides the shared HTTP client: explicit timeouts, retries
// with backoff, a configured User-Agent, size-limited JSON decoding and a
// simple per-source request spacing limiter.
package httpx

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/vasops/vulnwatch/internal/config"
)

// Client wraps a retrying HTTP client.
type Client struct {
	hc      *http.Client
	dl      *http.Client // Download: no overall timeout
	idle    time.Duration
	ua      string
	maxBody int64
	cfg     config.HTTP
	logger  *slog.Logger
}

// New builds a Client from the http config section. version replaces the
// {{version}} placeholder in the user agent.
func New(cfg config.HTTP, version string, logger *slog.Logger) *Client {
	maxBody := cfg.MaxResponseBytes
	if maxBody <= 0 {
		maxBody = 64 << 20
	}
	return &Client{
		hc:      retrying(cfg, logger, false),
		dl:      retrying(cfg, logger, true),
		idle:    cfg.Timeout.D(),
		ua:      strings.ReplaceAll(cfg.UserAgent, "{{version}}", version),
		maxBody: maxBody,
		cfg:     cfg,
		logger:  logger,
	}
}

// WithTimeout returns a copy of c whose requests may take up to d, for an
// API that is slow but answers (NVD). Zero keeps c.
func (c *Client) WithTimeout(d time.Duration) *Client {
	if d <= 0 || d == c.cfg.Timeout.D() {
		return c
	}
	cfg := c.cfg
	cfg.Timeout = config.Duration(d)
	n := *c
	n.cfg = cfg
	n.hc = retrying(cfg, c.logger, false)
	return &n
}

// retrying builds a retrying client. http.timeout bounds a whole request,
// or for downloads only the wait for the response headers (Download
// bounds the time between reads).
func retrying(cfg config.HTTP, logger *slog.Logger, download bool) *http.Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = cfg.Retries
	rc.RetryWaitMin = cfg.RetryBackoff.D()
	rc.RetryWaitMax = cfg.RetryBackoff.D() * 8
	rc.CheckRetry = checkRetry(rc.RetryWaitMax)
	rc.Backoff = backoff
	if !download {
		rc.HTTPClient.Timeout = cfg.Timeout.D()
	}
	if t, ok := rc.HTTPClient.Transport.(*http.Transport); ok {
		t.TLSClientConfig = TLSConfig()
		if download {
			t.ResponseHeaderTimeout = cfg.Timeout.D()
		}
	}
	rc.Logger = nil
	if logger != nil {
		rc.Logger = retryLogger{logger}
	}
	// Return the last response instead of a generic error so callers can
	// report the real status.
	rc.ErrorHandler = retryablehttp.PassthroughErrorHandler
	return rc.StandardClient()
}

// checkRetry retries what retryablehttp does (connection errors, 429, 5xx)
// plus a 403 that is a rate limit (GitHub, NVD). When the server asks to
// wait longer than maxWait, it gives up: the run reports the source as
// failed instead of stalling.
func checkRetry(maxWait time.Duration) retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		retry, cerr := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		if cerr != nil || err != nil || resp == nil {
			return retry, cerr
		}
		if resp.StatusCode == http.StatusForbidden && rateLimited(resp.Header) {
			retry = true
		}
		if wait, ok := serverWait(resp.Header, time.Now()); retry && ok && wait > maxWait {
			return false, nil
		}
		return retry, nil
	}
}

// backoff waits as long as the server asks (Retry-After, or the rate limit
// reset), at most maxWait; otherwise exponentially from minWait.
func backoff(minWait, maxWait time.Duration, attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if wait, ok := serverWait(resp.Header, time.Now()); ok {
			return min(wait, maxWait)
		}
	}
	return retryablehttp.DefaultBackoff(minWait, maxWait, attempt, nil)
}

// rateLimited reports whether a 403 says "slow down" rather than "no".
func rateLimited(h http.Header) bool {
	return h.Get("X-RateLimit-Remaining") == "0" || h.Get("Retry-After") != ""
}

// serverWait is how long the server asks to wait: Retry-After (seconds or
// an HTTP date), or with no requests left until X-RateLimit-Reset (Unix
// seconds, GitHub).
func serverWait(h http.Header, now time.Time) (time.Duration, bool) {
	if v := h.Get("Retry-After"); v != "" {
		if s, err := strconv.ParseInt(v, 10, 64); err == nil && s >= 0 {
			return time.Duration(s) * time.Second, true
		}
		if t, err := http.ParseTime(v); err == nil {
			return max(t.Sub(now), 0), true
		}
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if s, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return max(time.Unix(s, 0).Sub(now), 0), true
		}
	}
	return 0, false
}

// MinTLSVersion is the oldest TLS version vulnwatch speaks. Every service it
// calls (advisory APIs, Anthropic, Slack, registries) supports TLS 1.3; 1.2
// stays allowed for self-hosted Pushgateways and chart repositories.
const MinTLSVersion = tls.VersionTLS12

// TLSConfig is the client TLS configuration for every outbound connection.
func TLSConfig() *tls.Config { return &tls.Config{MinVersion: MinTLSVersion} }

// Plain returns an HTTP client without retries for SDKs that retry on their
// own (Anthropic, Slack), with the same TLS floor and a timeout.
func Plain(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = TLSConfig()
	return &http.Client{Transport: t, Timeout: timeout}
}

// retryLogger only surfaces retries; per-request debug noise is dropped.
// URLs in the arguments are redacted (query tokens, passwords).
type retryLogger struct{ l *slog.Logger }

func (r retryLogger) Error(msg string, kv ...any) { r.l.Warn(msg, redactArgs(kv)...) }
func (r retryLogger) Info(msg string, kv ...any)  {}
func (r retryLogger) Debug(msg string, kv ...any) {
	if strings.Contains(msg, "retrying") {
		r.l.Info(msg, redactArgs(kv)...)
	}
}
func (r retryLogger) Warn(msg string, kv ...any) { r.l.Warn(msg, redactArgs(kv)...) }

// HTTPClient exposes the underlying client for SDKs that accept one.
func (c *Client) HTTPClient() *http.Client { return c.hc }

// UserAgent returns the resolved User-Agent.
func (c *Client) UserAgent() string { return c.ua }

// StatusError is returned for non-2xx responses.
type StatusError struct {
	Method  string
	URL     string
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	m := cmp.Or(e.Method, http.MethodGet)
	if e.Message != "" {
		return fmt.Sprintf("%s %s: HTTP %d: %s", m, e.URL, e.Status, e.Message)
	}
	return fmt.Sprintf("%s %s: HTTP %d", m, e.URL, e.Status)
}

// Do sends req with the User-Agent set and returns the body for 2xx responses.
func (c *Client) Do(req *http.Request) ([]byte, http.Header, error) {
	body, h, err := c.open(req)
	if err != nil {
		return nil, h, err
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, h, bodyError(req, "read", err)
	}
	return b, h, nil
}

var htmlHeading = regexp.MustCompile(`(?is)<(h1|title)[^>]*>(.*?)</`)

// errorText is the reason in an error response's body, for logs and
// warnings: of an HTML page (a CDN's or proxy's error page, often with
// scripts) only its first heading or title, of anything else the first 300
// bytes.
func errorText(b []byte, contentType string) string {
	s := strings.TrimSpace(string(b))
	head := strings.ToLower(s[:min(len(s), 15)])
	if strings.Contains(contentType, "html") || strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") {
		m := htmlHeading.FindStringSubmatch(s)
		if m == nil {
			return ""
		}
		s = strings.Join(strings.Fields(m[2]), " ")
	}
	if len(s) > 300 {
		s = strings.ToValidUTF8(s[:300], "") + "…"
	}
	return s
}

// open sends req with the User-Agent set and returns the body of a 2xx
// response, limited to max_response_bytes, with the headers. Any other
// status is a StatusError.
func (c *Client) open(req *http.Request) (io.ReadCloser, http.Header, error) {
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, RedactError(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		msg := resp.Header.Get("message") // NVD puts the reason here
		if msg == "" {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			msg = errorText(b, resp.Header.Get("Content-Type"))
		}
		return nil, resp.Header, &StatusError{Method: req.Method, URL: redact(req), Status: resp.StatusCode, Message: msg}
	}
	return &cappedBody{ReadCloser: resp.Body, left: c.maxBody, err: &sizeError{url: redact(req), max: c.maxBody}}, resp.Header, nil
}

// sizeError is a response body beyond max_response_bytes.
type sizeError struct {
	url string
	max int64
}

func (e *sizeError) Error() string { return fmt.Sprintf("%s: response exceeds %d bytes", e.url, e.max) }

// cappedBody returns at most left bytes, then err if there is more.
type cappedBody struct {
	io.ReadCloser
	left int64
	err  *sizeError
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var one [1]byte
		n, err := b.ReadCloser.Read(one[:])
		if n > 0 || err == nil {
			return 0, b.err
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// decodeJSON sends req and stream-decodes the JSON body into out: the
// response is never held in memory as a whole.
func (c *Client) decodeJSON(req *http.Request, out any) (http.Header, error) {
	body, h, err := c.open(req)
	if err != nil {
		return h, err
	}
	defer body.Close()
	dec := json.NewDecoder(body)
	if err = dec.Decode(out); err == nil {
		// Read to the end: only whitespace may follow, within the size limit.
		if _, err = dec.Token(); errors.Is(err, io.EOF) {
			return h, nil
		}
		if err == nil {
			err = errors.New("data after the JSON value")
		}
	}
	return h, bodyError(req, "decode", err)
}

// bodyError wraps an error reading the body of req; the size limit error
// already names the URL.
func bodyError(req *http.Request, op string, err error) error {
	var se *sizeError
	if errors.As(err, &se) {
		return se
	}
	return fmt.Errorf("%s %s: %w", op, redact(req), err)
}

// redact keeps API keys and passwords in the URL out of errors (RedactURL).
func redact(req *http.Request) string { return RedactURL(req.URL.String()) }

// GetJSON fetches url and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, url string, headers map[string]string, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.decodeJSON(req, out)
}

// Download streams url into w, for files larger than max_response_bytes,
// and fails beyond limit bytes. There is no overall timeout, as a large file
// takes longer than http.timeout: the context bounds it, http.timeout
// bounds the wait for the headers and every pause in the body.
func (c *Client) Download(ctx context.Context, url string, w io.Writer, limit int64) (int64, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.dl.Do(req)
	if err != nil {
		return 0, RedactError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, &StatusError{Method: req.Method, URL: redact(req), Status: resp.StatusCode}
	}
	idle := cmp.Or(c.idle, time.Minute)
	stalled := fmt.Errorf("%s: no data for %s", redact(req), idle)
	timer := time.AfterFunc(idle, func() { cancel(stalled) })
	defer timer.Stop()
	n, err := io.Copy(w, io.LimitReader(idleReader{resp.Body, timer, idle}, limit+1))
	switch {
	case errors.Is(context.Cause(ctx), stalled):
		return n, stalled
	case err != nil:
		return n, fmt.Errorf("read %s: %w", redact(req), RedactError(err))
	case n > limit:
		return n, fmt.Errorf("%s: larger than %d bytes", redact(req), limit)
	}
	return n, nil
}

// idleReader restarts the stall timer on every read.
type idleReader struct {
	r     io.Reader
	timer *time.Timer
	idle  time.Duration
}

func (r idleReader) Read(p []byte) (int, error) {
	r.timer.Reset(r.idle)
	return r.r.Read(p)
}

// PostJSON posts in as JSON and decodes the response into out.
func (c *Client) PostJSON(ctx context.Context, url string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	_, err = c.decodeJSON(req, out)
	return err
}

// Limiter spaces requests at least interval apart. Safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func NewLimiter(interval time.Duration) *Limiter { return &Limiter{interval: interval} }

// Wait blocks until the next request slot or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil || l == nil || l.interval <= 0 {
		return err
	}
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()
	t := time.NewTimer(time.Until(slot))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
