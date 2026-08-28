package nacos

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"nacos3-scopehole/internal/httpx"
	"nacos3-scopehole/internal/jsonx"
)

const testToken = "tok123"

type recordedRequest struct {
	method, path, userAgent, accessToken string
	form                                 url.Values
}

type mockNacos struct {
	*httptest.Server
	mu                  sync.Mutex
	mode                string
	requests            []recordedRequest
	marker              string
	configReads         int
	markerCollisionHook func()
}

func (m *mockNacos) accessToken() string {
	if m.mode == "unsafe-token" {
		return "tok' ; echo injected ; '"
	}
	return testToken
}

func startMock(t *testing.T, mode string) *mockNacos {
	t.Helper()
	m := &mockNacos{mode: mode}
	m.Server = httptest.NewServer(m.handler())
	t.Cleanup(m.Close)
	return m
}

func (m *mockNacos) record(r *http.Request) {
	_ = r.ParseForm()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, recordedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		userAgent:   r.Header.Get("User-Agent"),
		accessToken: r.Header.Get("accessToken"),
		form:        r.Form,
	})
}

func (m *mockNacos) filtered() []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recordedRequest(nil), m.requests...)
}

func writeJSON(w http.ResponseWriter, status int, payload string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(payload))
}

func denied(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, `{"code":10001,"message":"access denied"}`)
}

func (m *mockNacos) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		token := r.Header.Get("accessToken")
		expectedToken := m.accessToken()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/nacos/v3/admin/cs/config/list":
			if m.mode == "open-auth" || token == expectedToken {
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":{"totalCount":1,"pageItems":[]}}`)
			} else {
				denied(w)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/nacos/v3/auth/user/list":
			switch m.mode {
			case "patched":
				denied(w)
			case "inconclusive":
				writeJSON(w, http.StatusInternalServerError, `{"code":500,"message":"boom"}`)
			default:
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":{"pageItems":[{"username":"nacos"},{"username":"auditor01"}]}}`)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/nacos/v3/admin/cs/config":
			if m.mode == "marker-collision" {
				if m.markerCollisionHook != nil {
					m.markerCollisionHook()
				}
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":{"content":"pre-existing"}}`)
				return
			}
			if token != expectedToken {
				denied(w)
				return
			}
			if m.mode == "unknown-marker-404" {
				writeJSON(w, http.StatusNotFound, `{"code":404,"message":"not found"}`)
				return
			}
			m.mu.Lock()
			content := m.marker
			if content != "" {
				m.configReads++
				if m.mode == "marker-changed" && m.configReads >= 2 {
					content = "changed-by-another-writer"
				}
				if m.mode == "readback-mismatch" {
					content = "unexpected-content"
				}
			}
			m.mu.Unlock()
			if content == "" {
				writeJSON(w, http.StatusNotFound, `{"code":20004,"message":"resource not found"}`)
				return
			}
			writeJSON(w, http.StatusOK,
				`{"code":0,"message":"success","data":{"createUser":"deployer","content":`+strconv.Quote(content)+`}}`)
		case r.Method == http.MethodPost:
			switch r.URL.Path {
			case "/nacos/v3/auth/user":
				if m.mode == "patched" {
					denied(w)
					return
				}
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":"create user ok!"}`)
			case "/nacos/v3/auth/role":
				if m.mode == "patched" {
					denied(w)
					return
				}
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":"add role ok!"}`)
			case "/nacos/v3/auth/permission":
				if m.mode == "patched" {
					denied(w)
					return
				}
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":"add permission ok!"}`)
			case "/nacos/v3/auth/user/login":
				writeJSON(w, http.StatusOK, `{"accessToken":`+strconv.Quote(expectedToken)+`,"tokenTtl":18000,"globalAdmin":false,"username":"deployer"}`)
			case "/nacos/v3/admin/cs/config":
				if token != expectedToken {
					denied(w)
					return
				}
				if m.mode == "config-write-fail" {
					writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":false}`)
					return
				}
				m.mu.Lock()
				m.marker = r.Form.Get("content")
				m.mu.Unlock()
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":true}`)
			default:
				writeJSON(w, http.StatusNotFound, `{"code":404}`)
			}
		case r.Method == http.MethodDelete:
			if m.mode == "cleanup-fail" {
				denied(w)
				return
			}
			if r.URL.Path == "/nacos/v3/admin/cs/config" {
				m.mu.Lock()
				m.marker = ""
				m.mu.Unlock()
				writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":true}`)
				return
			}
			writeJSON(w, http.StatusOK, `{"code":0,"message":"success","data":"delete ok!"}`)
		default:
			writeJSON(w, http.StatusNotFound, `{"code":404}`)
		}
	}
}

func baseURL(t *testing.T, m *mockNacos) string {
	t.Helper()
	return m.Server.URL + "/nacos"
}

func TestScanTargetStatuses(t *testing.T) {
	cases := []struct {
		mode       string
		wantStatus string
		wantIn     string
	}{
		{mode: "vulnerable", wantStatus: "vulnerable", wantIn: "leaked usernames: ['nacos', 'auditor01']"},
		{mode: "open-auth", wantStatus: "open-auth", wantIn: "admin scope openly accessible"},
		{mode: "patched", wantStatus: "protected", wantIn: "version and patch level were not inferred"},
		{mode: "inconclusive", wantStatus: "inconclusive", wantIn: "HTTP 500"},
	}
	hc := httpx.New()
	for _, tc := range cases {
		m := startMock(t, tc.mode)
		status, detail := ScanTarget(hc, baseURL(t, m), false, nil, nil)
		if status != tc.wantStatus {
			t.Fatalf("mode %s: status = %s, want %s", tc.mode, status, tc.wantStatus)
		}
		if !strings.Contains(detail, tc.wantIn) {
			t.Fatalf("mode %s: detail = %q, want substring %q", tc.mode, detail, tc.wantIn)
		}
	}
	status, detail := ScanTarget(hc, "http://127.0.0.1:1/nacos", false, nil, nil)
	if status != "unreachable" {
		t.Fatalf("unreachable status = %s (%s)", status, detail)
	}
}

func TestScanTargetRejectsHTMLSuccessPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nacos/v3/admin/cs/config/list" {
			denied(w)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer srv.Close()

	status, _ := ScanTarget(httpx.New(), srv.URL+"/nacos", false, nil, nil)
	if status != "inconclusive" {
		t.Fatalf("status = %q, want inconclusive", status)
	}
}

func TestUnrecognizedForbiddenResponseNeverOpensMutationGate(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		writeJSON(w, http.StatusForbidden, `{"code":1,"message":"access denied"}`)
	}))
	defer srv.Close()

	code := RunSingle(httpx.New(), srv.URL+"/nacos", srv.URL+"/nacos", false, false,
		&bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if got := posts.Load(); got != 0 {
		t.Fatalf("unrecognized denial allowed %d mutation request(s)", got)
	}
}

func TestRunSingleFullChain(t *testing.T) {
	m := startMock(t, "vulnerable")
	var out, errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d, out:\n%s\nerr:\n%s", code, out.String(), errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q", errOut.String())
	}
	for _, want := range []string{
		"REPRODUCED: unauthenticated account/role/permission creation succeeded.",
		"Write confirmed: exact marker content persisted.",
		"Cleaning up ephemeral test artifacts...",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q", want)
		}
	}

	var got []string
	for _, r := range m.filtered() {
		got = append(got, r.method+" "+r.path)
	}
	want := []string{
		"GET /nacos/v3/admin/cs/config/list",
		"POST /nacos/v3/auth/user",
		"POST /nacos/v3/auth/role",
		"POST /nacos/v3/auth/permission",
		"POST /nacos/v3/auth/user/login",
		"GET /nacos/v3/admin/cs/config/list",
		"GET /nacos/v3/admin/cs/config",
		"POST /nacos/v3/admin/cs/config",
		"GET /nacos/v3/admin/cs/config",
		"GET /nacos/v3/admin/cs/config",
		"DELETE /nacos/v3/admin/cs/config",
		"DELETE /nacos/v3/auth/permission",
		"DELETE /nacos/v3/auth/role",
		"DELETE /nacos/v3/auth/user",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("request order:\n got: %s\nwant: %s", strings.Join(got, "|"), strings.Join(want, "|"))
	}
}

func TestRunSingleEscapesUntrustedTokenAndOmitsShellCommand(t *testing.T) {
	m := startMock(t, "unsafe-token")
	var out bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, out:\n%s", code, out.String())
	}
	if want := "  token    : " + jsonx.Repr(m.accessToken()) + "\n"; !strings.Contains(out.String(), want) {
		t.Fatalf("escaped token line missing; want %q in:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "curl -H") {
		t.Fatalf("output contains a copyable shell command with an untrusted token:\n%s", out.String())
	}
}

func TestRunSingleUsesOrdinaryNamingAndBrowserUA(t *testing.T) {
	m := startMock(t, "vulnerable")
	RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &bytes.Buffer{}, &bytes.Buffer{})

	nameRe := regexp.MustCompile(`^[a-z]+[0-9a-f]{32}$`)
	markerRe := regexp.MustCompile(`^[a-z-]+-[0-9a-f]{32}\.yaml$`)
	var createUserForm, markerForm url.Values
	for _, r := range m.filtered() {
		if r.userAgent != httpx.UserAgent {
			t.Fatalf("User-Agent = %q", r.userAgent)
		}
		if strings.Contains(strings.ToLower(r.userAgent), "scopehole") {
			t.Fatalf("UA leaks tool identity: %q", r.userAgent)
		}
		switch r.method + " " + r.path {
		case "POST /nacos/v3/auth/user":
			createUserForm = r.form
			username := r.form.Get("username")
			if !nameRe.MatchString(username) {
				t.Fatalf("username = %q", username)
			}
			password := r.form.Get("password")
			if len(password) < 12 {
				t.Fatalf("password too short: %q", password)
			}
			if strings.Contains(strings.ToLower(password), "poc") {
				t.Fatalf("password leaks identity: %q", password)
			}
		case "POST /nacos/v3/admin/cs/config":
			markerForm = r.form
		}
	}
	if createUserForm == nil || markerForm == nil {
		t.Fatal("expected user creation and marker write requests")
	}
	dataId := markerForm.Get("dataId")
	if markerForm.Get("groupName") != "DEFAULT_GROUP" {
		t.Fatalf("groupName = %q", markerForm.Get("groupName"))
	}
	if !markerRe.MatchString(dataId) {
		t.Fatalf("dataId = %q", dataId)
	}
	content := markerForm.Get("content")
	if strings.Contains(strings.ToUpper(content), "QVD") || strings.Contains(strings.ToLower(content), "attacker") {
		t.Fatalf("marker content leaks identity: %q", content)
	}
	if !strings.Contains(content, "# shared runtime defaults") {
		t.Fatalf("marker content not ordinary YAML: %q", content)
	}
}

func TestRunSingleCheckOnlyModes(t *testing.T) {
	t.Run("vulnerable", func(t *testing.T) {
		m := startMock(t, "vulnerable")
		var out bytes.Buffer
		code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), true, false, &out, &bytes.Buffer{})
		if code != 0 {
			t.Fatalf("code = %d, out:\n%s", code, out.String())
		}
		if !strings.Contains(out.String(), "REPRODUCED (detection only): leaked usernames") ||
			!strings.Contains(out.String(), "Nothing was created, modified, or deleted on the target.") {
			t.Fatalf("out = %s", out.String())
		}
		if len(m.filtered()) != 2 {
			t.Fatalf("check-only must issue exactly 2 requests, got %d", len(m.filtered()))
		}
	})
	t.Run("patched", func(t *testing.T) {
		m := startMock(t, "patched")
		var out bytes.Buffer
		code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), true, false, &out, &bytes.Buffer{})
		if code != 1 || !strings.Contains(out.String(), "NOT REPRODUCED: user list is protected") {
			t.Fatalf("code = %d, out = %s", code, out.String())
		}
	})
}

func TestRunSingleChainRejections(t *testing.T) {
	t.Run("user creation rejected", func(t *testing.T) {
		m := startMock(t, "patched")
		var out bytes.Buffer
		code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
		if code != 1 || !strings.Contains(out.String(), "NOT REPRODUCED: request was rejected or the endpoint/path is unavailable.") {
			t.Fatalf("code = %d, out = %s", code, out.String())
		}
		if len(m.filtered()) != 2 {
			t.Fatalf("chain must stop after posture probe + rejected creation, got %d requests", len(m.filtered()))
		}
	})
	t.Run("open admin control", func(t *testing.T) {
		m := startMock(t, "open-auth")
		var out bytes.Buffer
		code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
		if code != 1 || !strings.Contains(out.String(), "refusing mutation") {
			t.Fatalf("code = %d, out = %s", code, out.String())
		}
		if len(m.filtered()) != 1 {
			t.Fatalf("expected only posture request, got %d", len(m.filtered()))
		}
	})
	t.Run("network error", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := RunSingle(httpx.New(), "http://127.0.0.1:1/nacos", "http://127.0.0.1:1/nacos", false, false, &out, &errOut)
		if code != 3 {
			t.Fatalf("code = %d", code)
		}
		if !strings.Contains(errOut.String(), "NETWORK ERROR") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})
}

func TestRunSingleConfigWriteFailureIsPartial(t *testing.T) {
	m := startMock(t, "config-write-fail")
	var out bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
	if code != 2 || !strings.Contains(out.String(), "PARTIAL") {
		t.Fatalf("code = %d, out = %s", code, out.String())
	}
}

func TestRunSingleCleanupFailureIsPartial(t *testing.T) {
	m := startMock(t, "cleanup-fail")
	var out, errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "cleanup warning") {
		t.Fatalf("code = %d, out = %s, err = %s", code, out.String(), errOut.String())
	}
}

func TestRunSingleRefusesExistingMarker(t *testing.T) {
	m := startMock(t, "marker-collision")
	var out bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
	if code != 2 {
		t.Fatalf("code = %d, out = %s", code, out.String())
	}
	for _, request := range m.filtered() {
		if request.method == http.MethodPost && request.path == "/nacos/v3/admin/cs/config" {
			t.Fatal("existing marker must not be overwritten")
		}
	}
}

func TestRunSingleRejectsUnrecognizedMarkerNotFound(t *testing.T) {
	m := startMock(t, "unknown-marker-404")
	var out bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &bytes.Buffer{})
	if code != 2 || !strings.Contains(out.String(), "marker absence could not be established") {
		t.Fatalf("code = %d, out = %s", code, out.String())
	}
	for _, request := range m.filtered() {
		if request.method == http.MethodPost && request.path == "/nacos/v3/admin/cs/config" {
			t.Fatal("unrecognized 404 must not authorize a marker write")
		}
	}
}

func TestRunSingleReadBackMismatchIsPartialAndPreservesMarker(t *testing.T) {
	m := startMock(t, "readback-mismatch")
	var out, errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &out, &errOut)
	if code != 2 || !strings.Contains(out.String(), "exact content read-back did not match") {
		t.Fatalf("code = %d, out = %s", code, out.String())
	}
	for _, request := range m.filtered() {
		if request.method == http.MethodDelete && request.path == "/nacos/v3/admin/cs/config" {
			t.Fatal("mismatched marker must not be deleted")
		}
	}
	if !strings.Contains(errOut.String(), "refusing to delete") {
		t.Fatalf("stderr = %s", errOut.String())
	}
}

func TestRunSinglePreservesMarkerChangedBeforeCleanup(t *testing.T) {
	m := startMock(t, "marker-changed")
	var errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &bytes.Buffer{}, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "refusing to delete") {
		t.Fatalf("code = %d, err = %s", code, errOut.String())
	}
	for _, request := range m.filtered() {
		if request.method == http.MethodDelete && request.path == "/nacos/v3/admin/cs/config" {
			t.Fatal("externally changed marker must not be deleted")
		}
	}
}

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

type switchableEntropyReader struct {
	fail atomic.Bool
}

func (r *switchableEntropyReader) Read(p []byte) (int, error) {
	if r.fail.Load() {
		return 0, errors.New("entropy unavailable after networking began")
	}
	clear(p)
	return len(p), nil
}

func TestRunSingleEntropyFailureStopsBeforeNetwork(t *testing.T) {
	original := entropyReader
	entropyReader = failingEntropyReader{}
	t.Cleanup(func() { entropyReader = original })

	m := startMock(t, "vulnerable")
	var errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &bytes.Buffer{}, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "RANDOMNESS ERROR") {
		t.Fatalf("code = %d, err = %s", code, errOut.String())
	}
	if len(m.filtered()) != 0 {
		t.Fatalf("entropy failure issued %d request(s)", len(m.filtered()))
	}
}

func TestRunSinglePreGeneratesCollisionMarkersBeforeNetwork(t *testing.T) {
	reader := &switchableEntropyReader{}
	original := entropyReader
	entropyReader = reader
	t.Cleanup(func() { entropyReader = original })

	m := startMock(t, "marker-collision")
	m.markerCollisionHook = func() { reader.fail.Store(true) }
	var errOut bytes.Buffer
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), false, false, &bytes.Buffer{}, &errOut)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if strings.Contains(errOut.String(), "RANDOMNESS ERROR") {
		t.Fatalf("entropy was consumed after network mutation began: %s", errOut.String())
	}
}

func TestRunSingleCheckOnlyDoesNotNeedEntropy(t *testing.T) {
	original := entropyReader
	entropyReader = failingEntropyReader{}
	t.Cleanup(func() { entropyReader = original })

	m := startMock(t, "vulnerable")
	code := RunSingle(httpx.New(), baseURL(t, m), baseURL(t, m), true, false, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 || len(m.filtered()) != 2 {
		t.Fatalf("code = %d, requests = %d", code, len(m.filtered()))
	}
}

func TestRunBatchMixed(t *testing.T) {
	vuln := startMock(t, "vulnerable")
	patched := startMock(t, "patched")
	entries := []TargetEntry{
		{Display: baseURL(t, vuln), Normalized: baseURL(t, vuln)},
		{Display: "bad host with spaces"},
		{Display: baseURL(t, patched), Normalized: baseURL(t, patched)},
	}
	var out bytes.Buffer
	code := RunBatch(httpx.New(), entries, 4, &out)
	if code != 0 {
		t.Fatalf("code = %d, out:\n%s", code, out.String())
	}
	wantSummary := "Summary: 1 vulnerable, 0 open-auth, 1 protected, 0 unreachable, 0 inconclusive, 1 invalid"
	if !strings.Contains(out.String(), wantSummary) {
		t.Fatalf("summary missing, out:\n%s", out.String())
	}
	lines := strings.Split(out.String(), "\n")
	vulnLine, protectedLine, invalidLine := -1, -1, -1
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "[VULNERABLE   ]"):
			vulnLine = i
		case strings.HasPrefix(line, "[PROTECTED    ]"):
			protectedLine = i
		case strings.HasPrefix(line, "[INVALID      ] bad host with spaces"):
			invalidLine = i
		}
	}
	if vulnLine < 0 || protectedLine < 0 || invalidLine < 0 {
		t.Fatalf("status lines missing:\n%s", out.String())
	}
	if !(vulnLine < protectedLine && protectedLine < invalidLine) {
		t.Fatalf("invalid entries must sort last:\n%s", out.String())
	}
}

func TestLoadTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "# comment\n\n10.0.0.5:8848\nhttp://10.0.0.6:8848/nacos\nbad host with spaces\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	if entries[0].Display != "10.0.0.5:8848" || entries[0].Normalized != "http://10.0.0.5:8848/nacos" {
		t.Fatalf("entry 0 = %+v", entries[0])
	}
	if entries[1].Normalized != "http://10.0.0.6:8848/nacos" {
		t.Fatalf("entry 1 = %+v", entries[1])
	}
	if entries[2].Normalized != "" {
		t.Fatalf("entry 2 should be invalid: %+v", entries[2])
	}
}

func TestSuccessful(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{200, `{"code":0,"message":"success"}`, true},
		{200, `{"code":200}`, true},
		{200, `{"code":0.0}`, true},
		{200, `{"code":0,"data":true}`, true},
		{200, `{"code":0,"data":false}`, false},
		{200, `{}`, false},
		{200, `{"message":"no code"}`, false},
		{200, `null`, false},
		{200, `not json`, false},
		{200, `{"code":"0"}`, false},
		{200, `{"code":500}`, false},
		{200, `{"code":true}`, false},
		{403, `{"code":0}`, false},
		{500, `{}`, false},
	}
	for _, tc := range cases {
		got := Successful(httpx.Response{Status: tc.status, Body: tc.body})
		if got != tc.want {
			t.Fatalf("Successful(%d, %s) = %v", tc.status, tc.body, got)
		}
	}
}

func TestExtractLogin(t *testing.T) {
	token, admin := ExtractLogin(httpx.Response{Body: `{"code":0,"data":{"accessToken":"t1","globalAdmin":true}}`})
	if token != "t1" || admin != true {
		t.Fatalf("wrapped login: %q, %v", token, admin)
	}
	token, admin = ExtractLogin(httpx.Response{Body: `{"accessToken":"t2","tokenTtl":18000,"globalAdmin":false}`})
	if token != "t2" || admin != false {
		t.Fatalf("top-level login: %q, %v", token, admin)
	}
	token, admin = ExtractLogin(httpx.Response{Body: `{}`, Header: http.Header{"Authorization": {"Bearer abc.def"}}})
	if token != "abc.def" || admin != nil {
		t.Fatalf("bearer fallback: %q, %v", token, admin)
	}
	token, admin = ExtractLogin(httpx.Response{Body: `{"code":0}`})
	if token != "" || admin != nil {
		t.Fatalf("no token: %q, %v", token, admin)
	}
}
