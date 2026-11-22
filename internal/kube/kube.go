// Package kube is a small read-only Kubernetes API client. client-go only
// loads the kubeconfig (or the in-cluster service account) and handles
// authentication; objects are read as plain JSON into the few fields
// vulnwatch needs.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client reads from one cluster.
type Client struct {
	Context string // kubeconfig context name ("in-cluster" inside a pod)
	host    string
	http    *http.Client
	maxSize int64
}

// ErrNotFound is returned when the API (e.g. a CRD) does not exist.
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned when the credentials may not read a resource.
var ErrForbidden = errors.New("forbidden")

// New loads the kubeconfig (path, else $KUBECONFIG, else ~/.kube/config;
// the in-cluster service account when there is none) and selects
// kubeContext (empty: the current context).
func New(path, kubeContext string, maxSize int64) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	name := kubeContext
	if name == "" {
		if raw, err := cc.RawConfig(); err == nil && raw.CurrentContext != "" {
			name = raw.CurrentContext
		} else {
			name = "in-cluster"
		}
	}
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &Client{Context: name, host: strings.TrimSuffix(cfg.Host, "/"), http: hc, maxSize: maxSize}, nil
}

// NewInCluster uses the pod's service account.
func NewInCluster(maxSize int64) (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("not running in a Kubernetes pod (%w)", err)
	}
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &Client{Context: "in-cluster", host: strings.TrimSuffix(cfg.Host, "/"), http: hc, maxSize: maxSize}, nil
}

// NewForTest returns a client for an httptest server.
func NewForTest(host string, hc *http.Client) *Client {
	return &Client{Context: "test", host: host, http: hc}
}

// Get decodes one object from path (e.g. "/version").
func (c *Client) Get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body io.Reader = resp.Body
	if c.maxSize > 0 {
		body = io.LimitReader(resp.Body, c.maxSize)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return fmt.Errorf("GET %s: %w", path, ErrNotFound)
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("GET %s: %w", path, ErrForbidden)
	default:
		msg, _ := io.ReadAll(io.LimitReader(body, 512))
		return fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(body).Decode(into); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
}

// List reads every item of a collection path (e.g. "/api/v1/pods"),
// following pagination in pages of pageSize items. selector is a label
// selector, may be empty.
func List[T any](ctx context.Context, c *Client, path, selector string, pageSize int) ([]T, error) {
	var (
		out  []T
		cont string
	)
	for {
		q := url.Values{"limit": {strconv.Itoa(pageSize)}}
		if selector != "" {
			q.Set("labelSelector", selector)
		}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := c.Get(ctx, path+"?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if cont = page.Metadata.Continue; cont == "" {
			return out, nil
		}
	}
}
