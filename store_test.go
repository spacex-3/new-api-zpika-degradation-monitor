package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir(), bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStoreEncryptsCredentialsAndPublicStateOmitsThem(t *testing.T) {
	store := testStore(t)
	baseURL := "https://private-upstream.example/v1"
	apiKey := "sk-private-monitor-key"
	barkURL := "https://bark.example/device-token"
	if err := store.SetBaseURL(baseURL); err != nil {
		t.Fatal(err)
	}
	if err := store.SetBarkURL(barkURL); err != nil {
		t.Fatal(err)
	}
	openedBarkURL, configured := store.BarkURL()
	if !configured || openedBarkURL != barkURL {
		t.Fatal("encrypted Bark URL did not round-trip")
	}
	target, err := store.AddTarget(TargetInput{
		Name: "VIP", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", IntervalMinutes: 120, RetainCount: 6,
		Enabled: true, APIKey: apiKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	stateData, err := os.ReadFile(store.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateData, []byte(baseURL)) || bytes.Contains(stateData, []byte(apiKey)) || bytes.Contains(stateData, []byte(barkURL)) {
		t.Fatal("state file contains plaintext credentials")
	}
	publicData, err := json.Marshal(store.PublicState(nil))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicData, []byte(baseURL)) || bytes.Contains(publicData, []byte(apiKey)) || bytes.Contains(publicData, []byte(target.EncryptedAPIKey)) {
		t.Fatal("public state exposes credential material")
	}
	_, openedURL, openedKey, err := store.TargetSecrets(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if openedURL != baseURL || openedKey != apiKey {
		t.Fatalf("decrypted values do not match")
	}
}

func TestHiddenTargetIsExcludedFromEveryPublicEndpoint(t *testing.T) {
	store := testStore(t)
	publicVisible := false
	target, err := store.AddTarget(TargetInput{
		Name: "Internal", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", CronExpression: "0 8-22/2 * * *", RetainCount: 6,
		Enabled: true, PublicVisible: &publicVisible, APIKey: "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := Result{ID: "result_hidden", TargetID: target.ID, TargetName: target.Name, Status: "succeeded", FinishedAt: time.Now().UTC()}
	if err := store.AddResult(result, "<html>hidden</html>"); err != nil {
		t.Fatal(err)
	}
	state := store.PublicState(nil)
	if len(state["targets"].([]map[string]any)) != 0 || len(state["results"].([]Result)) != 0 || len(state["history"].([]HistoryEntry)) != 0 {
		t.Fatalf("hidden target leaked through public state: %#v", state)
	}
	if _, ok := store.PublicResult(result.ID); ok {
		t.Fatal("hidden target result was publicly addressable")
	}
	if _, ok := store.Result(result.ID); !ok {
		t.Fatal("hidden target result disappeared from the admin store")
	}
}

func TestEmbedSecurityHeadersAllowOnlyConfiguredParents(t *testing.T) {
	origins, err := parseEmbedParentOrigins("https://api.example.com, https://vip.example.com")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{allowedHost: "monitor.example.com", embedParentOrigins: origins}
	handler := app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	embedResponse := httptest.NewRecorder()
	embedRequest := httptest.NewRequest(http.MethodGet, "https://monitor.example.com/embed", nil)
	handler.ServeHTTP(embedResponse, embedRequest)
	if embedResponse.Header().Get("X-Frame-Options") != "" || !strings.Contains(embedResponse.Header().Get("Content-Security-Policy"), "frame-ancestors https://api.example.com https://vip.example.com") {
		t.Fatalf("unexpected embed headers: %#v", embedResponse.Header())
	}

	adminResponse := httptest.NewRecorder()
	adminRequest := httptest.NewRequest(http.MethodGet, "https://monitor.example.com/admin", nil)
	handler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Header().Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(adminResponse.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("unexpected admin headers: %#v", adminResponse.Header())
	}

	if _, err := parseEmbedParentOrigins("http://insecure.example.com"); err == nil {
		t.Fatal("insecure embed origin was accepted")
	}
}

func TestArtifactSecurityHeadersAllowConfiguredEmbeddingChain(t *testing.T) {
	store := testStore(t)
	target, err := store.AddTarget(TargetInput{
		Name: "Visible", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", CronExpression: "0 8-22/2 * * *", RetainCount: 6,
		Enabled: true, APIKey: "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := Result{ID: "result_visible", TargetID: target.ID, TargetName: target.Name, Status: "succeeded", FinishedAt: time.Now().UTC()}
	if err := store.AddResult(result, "<html>visible artifact</html>"); err != nil {
		t.Fatal(err)
	}

	app := &App{
		store:              store,
		allowedHost:        "monitor.example.com",
		embedParentOrigins: []string{"https://console.example.com"},
	}
	handler := app.securityHeaders(http.HandlerFunc(app.publicArtifact))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://monitor.example.com/api/public/results/result_visible/artifact", nil)
	request.SetPathValue("id", result.ID)
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("artifact status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Header().Get("X-Frame-Options") != "" {
		t.Fatalf("artifact must not use X-Frame-Options: %#v", response.Header())
	}
	wantAncestors := "frame-ancestors 'self' https://console.example.com"
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), wantAncestors) {
		t.Fatalf("artifact CSP does not allow the configured embedding chain: %#v", response.Header())
	}
}

func TestCronScheduleUsesShanghaiWallClock(t *testing.T) {
	after := time.Date(2026, 11, 16, 7, 5, 8, 0, time.UTC)
	next, err := nextCronRun("0 */2 * * *", after)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next run = %s, want %s", next, want)
	}
	if legacyCronExpression(120) != "0 */2 * * *" || legacyCronExpression(30) != "*/30 * * * *" {
		t.Fatal("legacy intervals did not map to stable wall-clock cron expressions")
	}
	if _, err := normalizeCronExpression("*/5 * * * *", 0); err == nil {
		t.Fatal("cron interval below 10 minutes was accepted")
	}
	night, err := nextCronRun("0 8-20/2 * * 1-5", time.Date(2026, 11, 16, 14, 48, 0, 0, time.UTC))
	if err != nil || !night.Equal(time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("nighttime next run = %s, error = %v", night, err)
	}
	input, err := normalizeTargetInput(TargetInput{
		Name: "Cron Group", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", CronExpression: "*/30 * * * *", RetainCount: 6,
		APIKey: "test-key",
	}, true)
	if err != nil || input.IntervalMinutes != 30 {
		t.Fatalf("legacy interval hint = %d, error = %v", input.IntervalMinutes, err)
	}
}

func TestHistoryKeepsLatestSixtyAcrossTargets(t *testing.T) {
	store := testStore(t)
	for i := range 4 {
		store.state.Targets = append(store.state.Targets, Target{
			ID: fmt.Sprintf("target_%d", i), Name: fmt.Sprintf("Group %d", i), Enabled: true,
		})
	}
	for i := range 65 {
		result := Result{
			ID: fmt.Sprintf("result_%02d", i), TargetID: fmt.Sprintf("target_%d", i%4),
			TargetName: fmt.Sprintf("Group %d", i%4), Status: "succeeded", Quality: "normal",
			DurationMS: int64(i * 1000), InputTokens: int64(i * 10), OutputTokens: int64(i * 20), AttemptCount: 1,
			FinishedAt: time.Date(2026, 11, 16, 0, i, 0, 0, time.UTC),
		}
		if i == 63 {
			result.Quality = "degraded"
			result.Label = "疑似降智"
		}
		if i == 64 {
			result.Status = "failed"
			result.Quality = ""
		}
		if err := store.AddResult(result, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.state.History) != 60 || store.state.History[0].ID != "result_05" || store.state.History[59].ID != "result_64" {
		t.Fatalf("unexpected retained history: first=%s last=%s length=%d", store.state.History[0].ID, store.state.History[59].ID, len(store.state.History))
	}
	publicHistory, ok := store.PublicState(nil)["history"].([]HistoryEntry)
	if !ok || len(publicHistory) != 60 || publicHistory[0].ID != "result_64" || publicHistory[0].OutputTokens != 1280 || publicHistory[1].Quality != "degraded" {
		t.Fatalf("unexpected public history: %#v", publicHistory)
	}
}

func TestRunnerRetriesThreeTimesAndRestrictsFailureDetail(t *testing.T) {
	store := testStore(t)
	baseURL := "https://private-gateway.example/v1"
	apiKey := "private-key-without-standard-prefix"
	if err := store.SetBaseURL(baseURL); err != nil {
		t.Fatal(err)
	}
	target, err := store.AddTarget(TargetInput{
		Name: "Retry Group", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", IntervalMinutes: 120, RetainCount: 6,
		Enabled: true, APIKey: apiKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	notifications := 0
	notificationPath := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tests":
			posts++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "job_" + string(rune('0'+posts)), "status": "running"})
		case strings.HasPrefix(r.URL.Path, "/api/v1/tests/job_"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "failed", "phase": "complete",
				"error": "request to " + baseURL + " failed with api_key=" + apiKey,
			})
		case strings.HasPrefix(r.URL.Path, "/device/"):
			notifications++
			notificationPath = r.URL.Path
			_, _ = io.WriteString(w, `{"code":200}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if err := store.SetBarkURL(server.URL + "/device"); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(store, server.URL)
	runner.client = server.Client()
	runner.pollInterval = time.Millisecond
	runner.retryDelay = time.Millisecond
	if err := runner.run(t.Context(), target.ID); err == nil {
		t.Fatal("three failed attempts should return an error")
	}
	if posts != 3 || notifications != 1 {
		t.Fatalf("posts=%d notifications=%d, want 3 and 1", posts, notifications)
	}
	if strings.Contains(notificationPath, baseURL) || strings.Contains(notificationPath, apiKey) {
		t.Fatal("Bark notification contains credentials")
	}
	if len(store.state.Results) != 1 {
		t.Fatalf("stored %d results, want one final result", len(store.state.Results))
	}
	result := store.state.Results[0]
	if result.Status != "failed" || result.AttemptCount != 3 {
		t.Fatalf("unexpected final result: %#v", result)
	}
	if strings.Contains(result.FailureDetail, baseURL) || strings.Contains(result.FailureDetail, apiKey) {
		t.Fatal("stored failure detail contains credentials")
	}
	publicData, _ := json.Marshal(store.PublicState(nil))
	if bytes.Contains(publicData, []byte("failure_detail")) || !bytes.Contains(publicData, []byte(`"error":"请求失败"`)) {
		t.Fatalf("public state did not redact the failure: %s", publicData)
	}
	adminData, _ := json.Marshal(store.AdminState(nil))
	if !bytes.Contains(adminData, []byte("failure_detail")) || bytes.Contains(adminData, []byte(baseURL)) || bytes.Contains(adminData, []byte(apiKey)) {
		t.Fatalf("admin state has an invalid failure detail: %s", adminData)
	}
}

func TestRunnerRetriesThenNotifiesDegradedResult(t *testing.T) {
	store := testStore(t)
	if err := store.SetBaseURL("https://gateway.example/v1"); err != nil {
		t.Fatal(err)
	}
	target, err := store.AddTarget(TargetInput{
		Name: "Degraded Group", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", IntervalMinutes: 120, RetainCount: 6,
		Enabled: true, APIKey: "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	notifications := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tests":
			posts++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "job_" + string(rune('0'+posts)), "status": "running"})
		case strings.HasPrefix(r.URL.Path, "/api/v1/tests/job_") && posts < 3:
			_, _ = io.WriteString(w, `{"status":"failed","phase":"complete","error":"temporary failure"}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/tests/job_"):
			_, _ = io.WriteString(w, `{"status":"succeeded","phase":"complete","result":{"html":"<!doctype html>"},"assessment":{"quality":"degraded","label":"疑似降智","reason":"quality changed"}}`)
		case strings.HasPrefix(r.URL.Path, "/device/"):
			notifications++
			_, _ = io.WriteString(w, `{"code":200}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if err := store.SetBarkURL(server.URL + "/device"); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(store, server.URL)
	runner.client = server.Client()
	runner.pollInterval = time.Millisecond
	runner.retryDelay = time.Millisecond
	if err := runner.run(t.Context(), target.ID); err != nil {
		t.Fatal(err)
	}
	if posts != 3 || notifications != 1 {
		t.Fatalf("posts=%d notifications=%d, want 3 and 1", posts, notifications)
	}
	result := store.state.Results[0]
	if result.Status != "succeeded" || result.Quality != "degraded" || result.AttemptCount != 3 {
		t.Fatalf("unexpected recovered result: %#v", result)
	}
}

func TestBarkTestAndNotifyAllMode(t *testing.T) {
	store := testStore(t)
	notifications := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notifications++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200}`)
	}))
	defer server.Close()
	if err := store.SetBarkURL(server.URL + "/device"); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(store, server.URL)
	runner.client = server.Client()
	if err := runner.TestNotification(); err != nil {
		t.Fatal(err)
	}
	response := testResponse{}
	response.Assessment.Quality = "normal"
	response.Assessment.Label = "正常"
	runner.notifyResult(Result{TargetName: "Normal Group", Benchmark: "pelican"}, response)
	if notifications != 1 {
		t.Fatalf("normal result was sent in alerts-only mode: %d notifications", notifications)
	}
	if err := store.SetNotifyAll(true); err != nil {
		t.Fatal(err)
	}
	runner.notifyResult(Result{TargetName: "Normal Group", Benchmark: "pelican"}, response)
	if notifications != 2 {
		t.Fatalf("normal result was not sent in notify-all mode: %d notifications", notifications)
	}
	if notifyAll, ok := store.AdminState(nil)["notify_all"].(bool); !ok || !notifyAll {
		t.Fatal("notify-all mode was not exposed to the admin state")
	}
}

func TestRunnerArchivesSuccessfulPelicanResult(t *testing.T) {
	store := testStore(t)
	if err := store.SetBaseURL("https://gateway.example/v1"); err != nil {
		t.Fatal(err)
	}
	target, err := store.AddTarget(TargetInput{
		Name: "Group A", Benchmark: "pelican", Model: "gpt-6-astra",
		ReasoningEffort: "low", IntervalMinutes: 120, RetainCount: 2,
		Enabled: true, APIKey: "sk-test-only",
	})
	if err != nil {
		t.Fatal(err)
	}
	var submitted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &submitted)
			_, _ = io.WriteString(w, `{"id":"job_1","status":"running","phase":"generating"}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"job_1","benchmark":"pelican","status":"succeeded","phase":"complete","model":"gpt-6-astra","reasoning_effort":"low","result":{"html":"<!doctype html><title>safe artifact</title>","duration_ms":1234,"input_tokens":10,"output_tokens":20},"assessment":{"quality":"normal","label":"正常","reason":"分类结果为正常"}}`)
	}))
	defer server.Close()
	runner := NewRunner(store, server.URL)
	runner.pollInterval = time.Millisecond
	if err := runner.run(t.Context(), target.ID); err != nil {
		t.Fatal(err)
	}
	if submitted["base_url"] != "https://gateway.example/v1" || submitted["api_key"] != "sk-test-only" {
		t.Fatal("runner did not send decrypted server-side credentials")
	}
	result, ok := store.Result(store.state.Results[0].ID)
	if !ok || result.Quality != "normal" || result.ArtifactFile == "" {
		t.Fatalf("unexpected stored result: %#v", result)
	}
	artifact, err := store.Artifact(result)
	if err != nil || !strings.Contains(string(artifact), "safe artifact") {
		t.Fatalf("artifact was not archived: %v", err)
	}
}

func TestAuthRequiresValidSessionAndCSRF(t *testing.T) {
	adminToken := "test-admin-token-with-high-entropy-placeholder"
	hash := sha256.Sum256([]byte(adminToken))
	auth, err := NewAuth(hex.EncodeToString(hash[:]), bytes.Repeat([]byte{0x31}, 32), "https://monitor.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	claims, err := auth.issueSession(recorder)
	if err != nil {
		t.Fatal(err)
	}
	cookie := recorder.Result().Cookies()[0]
	called := false
	handler := auth.requireSession(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) })

	request := httptest.NewRequest(http.MethodPost, "https://monitor.example.com/api/admin/settings", strings.NewReader(`{}`))
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://monitor.example.com")
	request.Header.Set("X-CSRF-Token", claims.CSRF)
	handler(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("valid authenticated request was rejected")
	}

	called = false
	request = httptest.NewRequest(http.MethodPost, "https://monitor.example.com/api/admin/settings", strings.NewReader(`{}`))
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://monitor.example.com")
	rejected := httptest.NewRecorder()
	handler(rejected, request)
	if called || rejected.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token was not rejected: %d", rejected.Code)
	}
}
