package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "http://10.0.0.5:8848/nacos/", want: "http://10.0.0.5:8848/nacos"},
		{in: "http://10.0.0.5:8848/nacos///", want: "http://10.0.0.5:8848/nacos"},
		{in: "https://nacos.example.com", want: "https://nacos.example.com"},
		{in: "http://[::1]:8848/nacos", want: "http://[::1]:8848/nacos"},
		{in: "ftp://x", wantErr: true},
		{in: "http://", wantErr: true},
		{in: "http://ba d host", wantErr: true},
		{in: "//host/nacos", wantErr: true},
		{in: "http://host/nacos?tenant=x", wantErr: true},
		{in: "http://host/nacos#fragment", wantErr: true},
		{in: "http://host/nacos#", wantErr: true},
		{in: "http://host/nacos#/ignored", wantErr: true},
		{in: "http://user:pass@host/nacos", wantErr: true},
	}
	for _, tc := range cases {
		got, err := NormalizeBaseURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeBaseURL(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHTTPProxyHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HTTP_PROXY_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	_, _ = New().Do("POST", "http://nacos.invalid:8848/nacos/v3/auth/user", nil,
		map[string][]string{"username": {"generated-user"}, "password": {"generated-secret"}},
		map[string]string{"accessToken": "generated-token"})
}

func TestNewIgnoresAmbientHTTPProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer proxy.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTPProxyHelper$")
	env := make([]string, 0, len(os.Environ())+5)
	for _, item := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(item, "=", 2)[0])
		switch name {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "GO_WANT_HTTP_PROXY_HELPER":
			continue
		}
		env = append(env, item)
	}
	cmd.Env = append(env,
		"GO_WANT_HTTP_PROXY_HELPER=1",
		"HTTP_PROXY="+proxy.URL,
		"HTTPS_PROXY="+proxy.URL,
		"ALL_PROXY="+proxy.URL,
		"NO_PROXY=",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy helper: %v\n%s", err, output)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Fatalf("ambient proxy received %d authenticated request(s)", got)
	}
}

func TestDoSendsBrowserUAAndFormEncoding(t *testing.T) {
	var gotUA, gotAccept, gotCT, gotBody, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotCT = r.Header.Get("Content-Type")
		gotQuery = r.URL.RawQuery
		_ = r.ParseForm()
		gotBody = r.FormValue("a")
	}))
	defer srv.Close()

	c := New()
	resp, err := c.Do("POST", srv.URL+"/echo", map[string][]string{"q": {"1"}}, map[string][]string{"a": {"b"}}, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	if gotUA != UserAgent {
		t.Fatalf("User-Agent = %q", gotUA)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", gotCT)
	}
	if gotBody != "b" {
		t.Fatalf("form body a = %q", gotBody)
	}
	if gotQuery != "q=1" {
		t.Fatalf("query = %q", gotQuery)
	}
}

func TestDoReturnsNon2xxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":403}`))
	}))
	defer srv.Close()
	resp, err := New().Do("GET", srv.URL, nil, nil, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 403 || resp.Body != `{"code":403}` {
		t.Fatalf("resp = %d %q", resp.Status, resp.Body)
	}
}

func TestDoBlocksCrossOriginRedirect(t *testing.T) {
	sinkHits := 0
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinkHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusFound)
	}))
	defer source.Close()

	_, err := New().Do("GET", source.URL, nil, nil, map[string]string{"accessToken": "audit-secret"})
	if err == nil || !strings.Contains(err.Error(), "cross-origin redirect") {
		t.Fatalf("Do error = %v, want cross-origin redirect rejection", err)
	}
	if sinkHits != 0 {
		t.Fatalf("redirect target received %d request(s)", sinkHits)
	}
}

func TestDoAllowsSameOriginRedirect(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, serverURL+"/final", http.StatusFound)
			return
		}
		if got := r.Header.Get("accessToken"); got != "same-origin-token" {
			t.Fatalf("accessToken = %q", got)
		}
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()
	serverURL = srv.URL

	resp, err := New().Do("GET", srv.URL+"/start", nil, nil, map[string]string{"accessToken": "same-origin-token"})
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("Do = %+v, %v", resp, err)
	}
}

func TestDoRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 2<<20)))
	}))
	defer srv.Close()

	if _, err := New().Do("GET", srv.URL, nil, nil, nil); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestSummarizeRendersJSONAndTruncates(t *testing.T) {
	var buf bytes.Buffer
	Summarize(&buf, "t", Response{Status: 200, Body: `{"a":1}`})
	if got := buf.String(); got != "[t] HTTP 200: {\"a\": 1}\n" {
		t.Fatalf("Summarize = %q", got)
	}

	buf.Reset()
	long := `{"k":"` + strings.Repeat("x", 400) + `"}`
	Summarize(&buf, "t", Response{Status: 200, Body: long})
	line := buf.String()
	if !strings.HasSuffix(line, "...\n") || len(line) > 350 {
		t.Fatalf("long line not truncated: len=%d", len(line))
	}
}

func TestSummarizeFallsBackToRawBody(t *testing.T) {
	var buf bytes.Buffer
	Summarize(&buf, "t", Response{Status: 200, Body: "not json"})
	if got := buf.String(); got != "[t] HTTP 200: not json\n" {
		t.Fatalf("Summarize = %q", got)
	}
}

func TestSummarizeEscapesRawControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	Summarize(&buf, "t", Response{Status: 200, Body: "first\nsecond\x1b[31m"})
	if got := buf.String(); got != "[t] HTTP 200: first\\nsecond\\u001b[31m\n" {
		t.Fatalf("Summarize = %q", got)
	}
}

func TestSummarizeEscapesControlsAfterJSONRendering(t *testing.T) {
	var buf bytes.Buffer
	Summarize(&buf, "t", Response{Status: 200, Body: `{"message":"\u009b31m"}`})
	if got := buf.String(); got != "[t] HTTP 200: {\"message\": \"\\u009b31m\"}\n" {
		t.Fatalf("Summarize = %q", got)
	}
}

func TestJSONTagsNotEscaped(t *testing.T) {
	var buf bytes.Buffer
	Summarize(&buf, "t", Response{Status: 200, Body: `{"u":"<a>&b"}`})
	if !strings.Contains(buf.String(), "<a>&b") {
		t.Fatalf("HTML chars escaped: %q", buf.String())
	}
}

func TestHeaderCaseInsensitiveGet(t *testing.T) {
	h := http.Header{}
	h.Set("authorization", "Bearer tok")
	if got := h.Get("Authorization"); got != "Bearer tok" {
		_ = json.Marshal // keep import used if assertions change
		t.Fatalf("Get = %q", got)
	}
}
