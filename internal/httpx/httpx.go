// Package httpx wraps the small HTTP surface used against Nacos: one client,
// form/query encoding, default headers, base URL validation, and response
// summarizing.
package httpx

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"nacos3-scopehole/internal/jsonx"
)

const (
	RequestTimeout       = 8 * time.Second
	MaxResponseBodyBytes = int64(1 << 20)
	// UserAgent matches a current desktop browser so admin-scope requests
	// look like ordinary console traffic.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

var ErrResponseTooLarge = errors.New("response body exceeds limit")

// Response is a fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   string
}

// Client issues requests with a per-request timeout.
type Client struct {
	HTTP *http.Client
}

// New returns a ready-to-use client.
func New() *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Authentication material must go directly to the explicitly selected
	// target. Environment proxy variables are ambient process state and are
	// therefore not trusted as an authorization boundary.
	transport.Proxy = nil
	return &Client{HTTP: &http.Client{
		Timeout:   RequestTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				return fmt.Errorf("cross-origin redirect blocked: %s", req.URL.Redacted())
			}
			return nil
		},
	}}
}

func sameOrigin(left, right *url.URL) bool {
	if !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	effectivePort := func(value *url.URL) string {
		if value.Port() != "" {
			return value.Port()
		}
		if strings.EqualFold(value.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return effectivePort(left) == effectivePort(right)
}

// NormalizeBaseURL validates an absolute http(s) URL with a hostname and
// strips trailing slashes.
func NormalizeBaseURL(base string) (string, error) {
	if strings.ContainsAny(base, "?#") {
		return "", fmt.Errorf("base URL must not contain a query or a fragment")
	}
	normalized := strings.TrimRight(base, "/")
	parsed, err := url.Parse(normalized)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("base URL must be an absolute http(s) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("base URL must not contain user info, a query, or a fragment")
	}
	host := parsed.Hostname()
	for _, ch := range host {
		asciiAlnum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if ch > 127 || !(asciiAlnum || strings.ContainsRune(".-:", ch)) {
			return "", fmt.Errorf("invalid host in base URL: %s", jsonx.Repr(host))
		}
	}
	return normalized, nil
}

// Do sends one request. params are appended as the query string; form is sent
// as an urlencoded body. Headers override defaults.
func (c *Client) Do(method, rawURL string, params, form url.Values, headers map[string]string) (Response, error) {
	if len(params) > 0 {
		rawURL += "?" + params.Encode()
	}
	var payload io.Reader
	if form != nil {
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, rawURL, payload)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxResponseBodyBytes {
		return Response{}, fmt.Errorf("%w: maximum is %d bytes", ErrResponseTooLarge, MaxResponseBodyBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes+1))
	if err != nil {
		return Response{}, err
	}
	if int64(len(data)) > MaxResponseBodyBytes {
		return Response{}, fmt.Errorf("%w: maximum is %d bytes", ErrResponseTooLarge, MaxResponseBodyBytes)
	}
	return Response{
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   strings.ToValidUTF8(string(data), "\uFFFD"),
	}, nil
}

// Summarize prints one labeled response line, rendering JSON bodies with
// document key order and truncating long output.
func Summarize(w io.Writer, label string, resp Response) {
	rendered := resp.Body
	if parsed, err := jsonx.Parse(resp.Body); err == nil && parsed != nil {
		rendered = jsonx.Render(parsed)
	}
	rendered = jsonx.EscapeControls(rendered)
	if utf8.RuneCountInString(rendered) > 300 {
		rendered = string([]rune(rendered)[:300]) + "..."
	}
	fmt.Fprintf(w, "[%s] HTTP %d: %s\n", label, resp.Status, rendered)
}
