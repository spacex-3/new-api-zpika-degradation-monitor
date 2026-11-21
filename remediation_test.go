package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRemediationConfigurationSecurity(t *testing.T) {
	store := testStore(t)
	config := RemediationConfig{Enabled: true, SubURL: "https://sub.private.example", SubEmail: "admin@private.example", SubPassword: "private-password", NewURL: "https://new.private.example", NewToken: "private-token", NewUserID: 1}
	if err := store.SetRemediationConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRemediationConfig(RemediationConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	saved, err := store.RemediationConfig()
	if err != nil {
		t.Fatal(err)
	}
	if saved.SubPassword != config.SubPassword || saved.NewToken != config.NewToken || saved.FullTokenName != "鹈鹕-满血" {
		t.Fatal("blank fields did not keep saved credentials and defaults")
	}
	disk, err := os.ReadFile(store.statePath)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(store.PublicState(nil))
	admin, _ := json.Marshal(store.AdminState(nil))
	for _, secret := range []string{config.SubURL, config.SubEmail, config.SubPassword, config.NewURL, config.NewToken} {
		for _, data := range [][]byte{disk, public, admin} {
			if strings.Contains(string(data), secret) {
				t.Fatal("credentials exposed")
			}
		}
	}
	for _, bad := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/api", "https://example.com?token=secret", "https://example.com/#secret"} {
		if err := store.SetRemediationConfig(RemediationConfig{SubURL: bad}); err == nil {
			t.Errorf("accepted invalid address %q", bad)
		}
	}
	// Authentication, Origin, CSRF and reauthentication apply to all new routes.
	hash := sha256.Sum256([]byte("test-admin"))
	auth, err := NewAuth(hex.EncodeToString(hash[:]), make([]byte, 32), "https://monitor.example", false)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(store, "https://unused.example")
	app := &App{store: store, runner: runner, auth: auth}
	issued := httptest.NewRecorder()
	claims, err := auth.issueSession(issued)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path         string
		cookie, csrf, origin bool
		body                 string
		want                 int
	}{
		{"GET", "/api/admin/remediation", false, false, false, "", 401},
		{"POST", "/api/admin/remediation/test", false, false, false, "", 401},
		{"PUT", "/api/admin/remediation", true, false, true, `{}`, 403},
		{"POST", "/api/admin/remediation/test", true, true, false, `{}`, 403},
		{"PUT", "/api/admin/remediation", true, true, true, `{"admin_token":"wrong"}`, 401},
		{"PUT", "/api/admin/remediation", true, true, true, `{"enabled":false,"admin_token":"test-admin"}`, 200},
		{"GET", "/api/admin/remediation", true, false, false, "", 200},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.cookie {
			req.AddCookie(issued.Result().Cookies()[0])
		}
		if tc.csrf {
			req.Header.Set("X-CSRF-Token", claims.CSRF)
		}
		if tc.origin {
			req.Header.Set("Origin", "https://monitor.example")
		}
		response := httptest.NewRecorder()
		app.routes().ServeHTTP(response, req)
		if response.Code != tc.want {
			t.Fatalf("%s %s got %d want %d: %s", tc.method, tc.path, response.Code, tc.want, response.Body.String())
		}
		if strings.Contains(response.Body.String(), config.SubURL) || strings.Contains(response.Body.String(), config.NewToken) {
			t.Fatal("credential echoed")
		}
	}
}

func TestTeamStatsBuckets(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	expired := now.Unix() - 1
	var stats teamStats
	for _, account := range []subAccount{
		{Status: "active", Schedulable: true},
		{Status: "active", Schedulable: true, RateLimitResetAt: &past},
		{Status: "active", Schedulable: true, RateLimitResetAt: &future},
		{Status: "error", Schedulable: true, RateLimitResetAt: &future},
		{Status: "disabled", Schedulable: true},
		{Status: "active", Schedulable: false},
		{Status: "active", Schedulable: true, OverloadUntil: &future},
		{Status: "active", Schedulable: true, TempUnschedulableUntil: &future},
		{Status: "active", Schedulable: true, ExpiresAt: &expired},
	} {
		stats.count(account, now)
	}
	if stats != (teamStats{Available: 2, RateLimited: 1, Other: 6, Total: 9}) {
		t.Fatalf("incorrect stats: %+v", stats)
	}
	if stats.String() != "team分组：可用:2个账号，限流:1个账号，总量:9个账号，其他不可用:6个账号" {
		t.Fatal(stats.String())
	}
}

// Complete mocked workflow including the existing first Bark, final Bark,
// cached-token correlation, ambiguous matches, retries and non-recursive recheck.
func TestAutomaticRemediationWorkflow(t *testing.T) {
	for _, tc := range []struct {
		name, mode     string
		writes, checks int
		message        string
	}{
		{"migrates and verifies group", "ok", 1, 2, "分组复检正常"},
		{"other channel is untouched", "channel", 0, 1, "未命中 #23"},
		{"ambiguous newapi log", "new-ambiguous", 0, 1, "newapi 请求匹配到 2 条"},
		{"incomplete newapi page", "new-incomplete", 0, 1, "分页不完整"},
		{"ambiguous sub2api log", "sub-ambiguous", 0, 1, "sub2api 请求匹配到 2 条"},
		{"overlapping sub2api pages", "sub-overlap", 0, 1, "分页重叠或无效"},
		{"cached tokens must agree", "tokens", 0, 1, "sub2api 请求匹配到 0 条"},
		{"account already moved", "moved", 0, 1, "账号当前已不在 team"},
		{"failed PUT applied then verified", "applied-error", 1, 2, "分组复检正常"},
		{"uncertain PUT not repeated", "write-error", 1, 1, "迁移结果未能确认"},
		{"degraded recheck no cascade", "still-degraded", 1, 2, "本轮不再迁移其他账号"},
		{"recheck retries bounded", "recheck-failed", 1, 4, "复检连续请求失败"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testStore(t)
			var mu sync.Mutex
			checks, writes := 0, 0
			groups := []int64{15, 7}
			if tc.mode == "moved" {
				groups = []int64{17}
			}
			finished := time.Now().UTC().Truncate(time.Second)
			var notifications []string
			subCalls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch {
				case req.URL.Path == "/api/v1/auth/login":
					var input map[string]string
					_ = json.NewDecoder(req.Body).Decode(&input)
					if input["email"] != "admin@example.com" || input["password"] != "private-password" {
						t.Error("login credentials missing")
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]string{"access_token": "session-secret"}})
				case req.URL.Path == "/api/v1/admin/groups/all":
					writeJSON(w, 200, map[string]any{"code": 0, "data": []subGroup{{15, "team", "openai"}, {18, "降智", "openai"}}})
				case req.URL.Path == "/api/log/":
					if req.Header.Get("Authorization") != "Bearer admin-secret" || req.Header.Get("New-Api-User") != "1" {
						t.Error("newapi admin credentials missing")
					}
					item := newUsage{ID: 100, CreatedAt: finished.Unix(), Group: "codex-满血不降智", TokenName: "鹈鹕-满血", Model: "gpt-6.1-sol", Channel: 23, ChannelName: "sub2api_pro", InputTokens: 4328, OutputTokens: 2239}
					if tc.mode == "channel" {
						item.Channel = 113
						item.ChannelName = "another"
					}
					items := []newUsage{item}
					total := 1
					if tc.mode == "new-ambiguous" {
						item.ID++
						items = append(items, item)
						total = 2
					}
					if tc.mode == "new-incomplete" {
						total = 101
					}
					writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"total": total, "items": items}})
				case req.URL.Path == "/api/v1/admin/usage":
					subCalls++
					if req.Header.Get("Authorization") != "Bearer session-secret" || req.URL.Query().Get("group_id") != "15" {
						t.Error("sub2api auth/filter missing")
					}
					item := subUsage{ID: 200, AccountID: 99, GroupID: 15, Model: "gpt-6.1-sol", CreatedAt: finished, InputTokens: 232, CacheReadTokens: 4096, OutputTokens: 2239}
					if tc.mode == "tokens" {
						item.CacheReadTokens = 1
					}
					// First page is full. The deliberately approximate total must
					// not cause the second page (with the match) to be skipped.
					if req.URL.Query().Get("page") == "1" {
						a, b := item, item
						a.ID = 198
						a.OutputTokens = 9
						b.ID = 199
						b.OutputTokens = 10
						writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"total": 2, "page_size": 2, "items": []subUsage{a, b}}})
						return
					}
					items := []subUsage{item}
					if tc.mode == "sub-overlap" {
						items[0].ID = 199
					}
					if tc.mode == "sub-ambiguous" {
						item.ID = 203
						items = append(items, item)
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"total": 3, "page_size": 1000, "items": items}})
				case req.URL.Path == "/api/v1/admin/accounts/99":
					if req.Method == "PUT" {
						writes++
						var input struct {
							GroupIDs []int64 `json:"group_ids"`
						}
						_ = json.NewDecoder(req.Body).Decode(&input)
						if !sameGroupIDs(input.GroupIDs, []int64{7, 18}) {
							t.Errorf("did not preserve unrelated groups: %v", input.GroupIDs)
						}
						if tc.mode != "write-error" {
							groups = input.GroupIDs
						}
						if tc.mode == "write-error" || tc.mode == "applied-error" {
							w.WriteHeader(504)
							return
						}
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": subAccount{ID: 99, Platform: "openai", GroupIDs: groups, Status: "active", Schedulable: true}})
				case req.URL.Path == "/api/v1/admin/accounts":
					if req.URL.Query().Get("group") != "15" || req.URL.Query().Get("lite") != "true" {
						t.Error("wrong stats group filter")
					}
					items := make([]subAccount, 14)
					future := time.Now().Add(time.Hour)
					for i := range items {
						items[i] = subAccount{ID: int64(i + 1), Platform: "openai", GroupIDs: []int64{15}, Status: "active", Schedulable: true}
						if i >= 11 {
							items[i].RateLimitResetAt = &future
						}
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"total": 14, "page_size": 1000, "items": items}})
				case req.URL.Path == "/api/v1/tests" && req.Method == "POST":
					checks++
					writeJSON(w, 200, map[string]any{"id": "test", "status": "running"})
				case req.URL.Path == "/api/v1/tests/test":
					quality := "degraded"
					if checks > 1 && tc.mode != "still-degraded" {
						quality = "normal"
					}
					status := "succeeded"
					if checks > 1 && tc.mode == "recheck-failed" {
						status = "failed"
					}
					writeJSON(w, 200, map[string]any{"status": status, "phase": "complete", "model": "gpt-6.1-sol", "started_at": finished.Add(-time.Minute).Format(time.RFC3339Nano), "finished_at": finished.Format(time.RFC3339Nano), "input_tokens": 4328, "output_tokens": 2239, "assessment": map[string]string{"quality": quality, "label": "参考"}})
				case strings.HasPrefix(req.URL.Path, "/device/"):
					notifications = append(notifications, req.URL.Path)
					writeJSON(w, 200, map[string]int{"code": 200})
				default:
					t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			if err := store.SetBaseURL(server.URL + "/v1"); err != nil {
				t.Fatal(err)
			}
			if err := store.SetBarkURL(server.URL + "/device"); err != nil {
				t.Fatal(err)
			}
			target, err := store.AddTarget(TargetInput{Name: "codex-满血不降智", Benchmark: "pelican", Model: "gpt-6.1-sol", ReasoningEffort: "low", IntervalMinutes: 120, RetainCount: 6, Enabled: true, APIKey: "sk-monitor-secret"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetRemediationConfig(RemediationConfig{Enabled: true, SubURL: server.URL, SubEmail: "admin@example.com", SubPassword: "private-password", NewURL: server.URL, NewToken: "admin-secret", NewUserID: 1}); err != nil {
				t.Fatal(err)
			}
			runner := NewRunner(store, server.URL)
			runner.client = server.Client()
			runner.pollInterval = time.Nanosecond
			runner.retryDelay = 0
			if err := runner.run(context.Background(), target.ID); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if writes != tc.writes || checks != tc.checks {
				t.Fatalf("writes=%d checks=%d; want %d,%d", writes, checks, tc.writes, tc.checks)
			}
			if tc.writes > 0 && subCalls < 2 {
				t.Error("pagination was not exhausted")
			}
			if len(notifications) != 2 || !strings.Contains(notifications[0], "检测到疑似降智") || !strings.Contains(notifications[1], tc.message) || !strings.Contains(notifications[1], "team分组：可用:11个账号，限流:3个账号，总量:14个账号") {
				t.Fatalf("unexpected notifications: %v", notifications)
			}
			mu.Unlock()
			events := store.AdminState(nil)["remediations"].([]RemediationEvent)
			if len(events) != 1 || !strings.Contains(events[0].Message, tc.message) {
				t.Fatalf("audit missing outcome: %+v", events)
			}
			if tc.mode == "write-error" {
				if events[0].State != "uncertain" {
					t.Fatal("uncertainty not preserved")
				}
				// A different detection cannot retry an uncertain account migration.
				original, _ := store.Result(events[0].ResultID)
				original.ID = "other-result"
				runner.remediate(context.Background(), original)
				if writes != 1 {
					t.Fatal("uncertain mutation was repeated")
				}
			}
			// Replaying the original detection after a restart is also read-only.
			reopened, err := NewStore(store.dataDir, store.key)
			if err != nil {
				t.Fatal(err)
			}
			restarted := NewRunner(reopened, server.URL)
			restarted.client = server.Client()
			original, _ := store.Result(events[0].ResultID)
			restarted.remediate(context.Background(), original)
			if writes != tc.writes {
				t.Fatal("replayed migration after restart")
			}
		})
	}
}

func TestRemediationRedirectAndPublicIsolation(t *testing.T) {
	var leaked bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(200) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer source.Close()
	runner := NewRunner(testStore(t), source.URL)
	runner.client = source.Client()
	client := runner.remediationClient(RemediationConfig{SubURL: source.URL, SubEmail: "secret-email", SubPassword: "secret-password", NewURL: source.URL, NewToken: "secret-token"})
	if err := client.login(context.Background()); err == nil || strings.Contains(err.Error(), source.URL) || strings.Contains(err.Error(), "secret-password") {
		t.Fatal("redirect was followed or exposed details")
	}
	if leaked {
		t.Fatal("credentials sent to redirect destination")
	}
	store := runner.store
	event := RemediationEvent{ResultID: "private-result", AccountID: 99, State: "uncertain", Message: "private-account-audit"}
	if err := store.saveRemediation(event, true); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(store.PublicState(nil))
	if strings.Contains(string(public), event.Message) || strings.Contains(string(public), event.ResultID) {
		t.Fatal("private audit exposed publicly")
	}
	// Unfinished claims survive pruning and a restart.
	for i := range 105 {
		if err := store.saveRemediation(RemediationEvent{ResultID: strings.Repeat("x", i+1), State: "completed"}, true); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := NewStore(store.dataDir, store.key)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(reopened.state.Remediations, func(e RemediationEvent) bool { return e.ResultID == event.ResultID }) {
		t.Fatal("uncertain migration claim pruned")
	}
}

func TestRemediationSerializesDuplicateDetections(t *testing.T) {
	store := testStore(t)
	var loginCount int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both concurrent workflows have the same result ID. Only one may
		// reach the API, even if the initial login fails.
		loginCount++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	if err := store.SetRemediationConfig(RemediationConfig{Enabled: true, SubURL: server.URL, SubEmail: "admin@example.com", SubPassword: "password", NewURL: server.URL, NewToken: "admin-token", NewUserID: 1}); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(store, server.URL)
	runner.client = server.Client()
	result := Result{ID: "duplicate", TargetName: "codex-不降智", Status: "succeeded", Quality: "degraded"}
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() { defer wg.Done(); runner.remediate(context.Background(), result) }()
	}
	wg.Wait()
	if loginCount != 1 {
		t.Fatalf("concurrent result processed %d times", loginCount)
	}
}

func TestTeamStatsDoesNotFabricateZeros(t *testing.T) {
	for _, payload := range []string{`{"code":0,"data":null}`, `{"code":0,"data":{"items":[],"page_size":1000}}`, `{"code":0,"data":{"total":1,"items":[],"page_size":1000}}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		}))
		runner := NewRunner(testStore(t), server.URL)
		runner.client = server.Client()
		client := runner.remediationClient(RemediationConfig{SubURL: server.URL})
		if _, err := client.teamStats(context.Background(), 15); err == nil {
			t.Fatal("invalid statistics response reported as zero")
		}
		server.Close()
	}
}

func TestSubReportScheduleAndPersistence(t *testing.T) {
	store := testStore(t)
	defaults := store.SubReport()
	if defaults.Enabled || defaults.CronExpression != "0 8-22/2 * * *" || defaults.TeamMinimum != 5 || defaults.DegradedMinimum != 1 {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}
	// Asia/Shanghai, including weekends, without affecting target schedules.
	for _, day := range []string{"2026-11-20", "2026-11-21"} {
		now, _ := time.Parse(time.RFC3339, day+"T07:59:00+08:00")
		for _, hour := range []int{8, 10, 12, 14, 16, 18, 20, 22} {
			next, err := nextCronRun(defaultSubReportCron, now)
			if err != nil || next.In(time.FixedZone("Asia/Shanghai", 8*3600)).Hour() != hour {
				t.Fatalf("cron hour mismatch: %s %v", next, err)
			}
			now = next
		}
		next, err := nextCronRun(defaultSubReportCron, now)
		if err != nil || next.Sub(now) != 10*time.Hour {
			t.Fatalf("nighttime reports scheduled: %s %v", next, err)
		}
	}
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	input := SubReportInput{Enabled: true, CronExpression: defaultSubReportCron, TeamMinimum: 5, DegradedMinimum: 1}
	if err := store.SetSubReport(input, now); err == nil {
		t.Fatal("enabled without credentials")
	}
	if err := store.SetRemediationConfig(RemediationConfig{SubURL: "https://sub.example", SubEmail: "admin@example.com", SubPassword: "private-password"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubReport(input, now); err == nil {
		t.Fatal("enabled without Bark endpoint")
	}
	if err := store.SetBarkURL("https://bark.example/device-key"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubReport(input, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	config := store.SubReport()
	if !config.NextRunAt.Equal(now) {
		t.Fatal("wrong initial slot")
	}
	if err := store.SetSubReport(input, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !store.SubReport().NextRunAt.Equal(now) {
		t.Fatal("saving unchanged schedule skipped a due slot")
	}
	statePath := store.statePath
	store.statePath = store.dataDir + "/missing/state.json"
	if _, due, err := store.claimSubReport(now); err == nil || due {
		t.Fatal("claimed report before durable slot persistence")
	}
	store.statePath = statePath
	if !store.SubReport().NextRunAt.Equal(now) {
		t.Fatal("failed persistence advanced report schedule")
	}
	var wg sync.WaitGroup
	var claims int
	var mu sync.Mutex
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, due, err := store.claimSubReport(now.Add(20 * time.Second))
			if err != nil {
				t.Error(err)
			}
			if due {
				mu.Lock()
				claims++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claims != 1 {
		t.Fatalf("slot claimed %d times", claims)
	}
	reopened, err := NewStore(store.dataDir, store.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, due, err := reopened.claimSubReport(now.Add(30 * time.Second)); err != nil || due {
		t.Fatal("slot replayed after restart")
	}
	// A restart late at night skips the overdue daytime slot.
	night := now.Add(15 * time.Hour)
	if _, due, err := reopened.claimSubReport(night); err != nil || due {
		t.Fatal("overdue report replayed at night")
	}
	if !reopened.SubReport().NextRunAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatal("next daytime slot incorrect")
	}
	for _, bad := range []SubReportInput{
		{CronExpression: "* * * * *"}, {CronExpression: "invalid"}, {CronExpression: defaultSubReportCron, TeamMinimum: -1}, {CronExpression: defaultSubReportCron, DegradedMinimum: 10001},
	} {
		if err := store.SetSubReport(bad, now); err == nil {
			t.Fatal("accepted invalid report settings")
		}
	}
	input.Enabled = false
	if err := store.SetSubReport(input, now); err != nil {
		t.Fatal(err)
	}
	if _, due, err := store.claimSubReport(now.Add(48 * time.Hour)); err != nil || due {
		t.Fatal("disabled schedule sent report")
	}
	public, _ := json.Marshal(store.PublicState(nil))
	if strings.Contains(string(public), "sub_report") {
		t.Fatal("administrator report settings leaked publicly")
	}
}

func TestSubReportMessagesAndDelivery(t *testing.T) {
	for _, tc := range []struct {
		name, mode     string
		team, degraded int
		warning        bool
	}{
		{"healthy boundary", "ok", 5, 1, false},
		{"team low", "ok", 4, 1, true},
		{"degraded low", "ok", 5, 0, true},
		{"both low", "ok", 0, 0, true},
		{"unknown group", "missing", 5, 1, true},
		{"ambiguous group", "ambiguous", 5, 1, true},
		{"partial stats failure", "stats-fail", 5, 1, true},
		{"login failure", "login-fail", 5, 1, true},
		{"Bark failure", "bark-fail", 5, 1, false},
		{"free spans multiple pages", "free-pages", 5, 1, false},
		{"zero thresholds disable shortage warning", "zero-thresholds", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testStore(t)
			var delivered string
			barkCalls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/api/v1/auth/login":
					if tc.mode == "login-fail" {
						w.WriteHeader(401)
						return
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]string{"access_token": "secret-session"}})
				case "/api/v1/admin/groups/all":
					groups := []subGroup{{15, "team", "openai"}, {18, "降智", "openai"}, {19, "free", "openai"}}
					if tc.mode == "missing" {
						groups = groups[:2]
					}
					if tc.mode == "ambiguous" {
						groups = append(groups, subGroup{20, "team", "openai"})
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": groups})
				case "/api/v1/admin/accounts":
					if req.Method != "GET" || req.Header.Get("Authorization") != "Bearer secret-session" {
						t.Error("invalid read-only stats request")
					}
					group := req.URL.Query().Get("group")
					if tc.mode == "stats-fail" && group == "15" {
						w.WriteHeader(503)
						return
					}
					count, id := 0, int64(15)
					switch group {
					case "15":
						count = tc.team
					case "18":
						count = tc.degraded
						id = 18
					case "19":
						id = 19
						if tc.mode == "free-pages" {
							count = 2
						}
					default:
						t.Error("unexpected group")
					}
					items := make([]subAccount, 0, count)
					for i := range count {
						items = append(items, subAccount{ID: int64(i + 1), Platform: "openai", GroupIDs: []int64{id}, Status: "active", Schedulable: true})
					}
					if tc.mode == "free-pages" && group == "19" {
						if req.URL.Query().Get("page") == "1" {
							items = items[:1]
						} else {
							items = items[1:]
						}
						writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"items": items, "total": 2, "page_size": 1}})
						return
					}
					writeJSON(w, 200, map[string]any{"code": 0, "data": map[string]any{"items": items, "total": count, "page_size": 1000}})
				default:
					if !strings.HasPrefix(req.URL.Path, "/device/") {
						t.Errorf("unexpected API/write %s %s", req.Method, req.URL.Path)
						w.WriteHeader(404)
						return
					}
					barkCalls++
					delivered = req.URL.Path
					if tc.mode == "bark-fail" {
						w.WriteHeader(500)
						return
					}
					writeJSON(w, 200, map[string]int{"code": 200})
				}
			}))
			defer server.Close()
			if err := store.SetRemediationConfig(RemediationConfig{SubURL: server.URL, SubEmail: "admin@example.com", SubPassword: "private-password"}); err != nil {
				t.Fatal(err)
			}
			if err := store.SetBarkURL(server.URL + "/device"); err != nil {
				t.Fatal(err)
			}
			runner := NewRunner(store, server.URL)
			runner.client = server.Client()
			config := store.SubReport()
			if tc.mode == "zero-thresholds" {
				config.TeamMinimum, config.DegradedMinimum = 0, 0
			}
			message, err := runner.sendSubReport(context.Background(), config)
			if (err != nil) != (tc.mode == "bark-fail") {
				t.Fatalf("delivery error mismatch: %v", err)
			}
			if barkCalls != 1 {
				t.Fatalf("sent %d Bark requests", barkCalls)
			}
			if strings.Contains(delivered, "⚠️") != tc.warning {
				t.Fatalf("incorrect warning title: %s", delivered)
			}
			for _, name := range []string{"team", "降智", "free"} {
				if !strings.Contains(message, name+"分组：") {
					t.Fatalf("missing %s stats", name)
				}
			}
			if tc.mode == "ok" || tc.mode == "bark-fail" {
				if strings.Contains(message, "team 可用仅") != (tc.team < 5) || strings.Contains(message, "降智 可用仅") != (tc.degraded < 1) {
					t.Fatal("threshold warning mismatch")
				}
				if !strings.Contains(message, "free分组：可用:0个账号") {
					t.Fatal("empty free group not counted")
				}
			}
			if tc.mode == "stats-fail" && (!strings.Contains(message, "team分组：统计读取失败") || !strings.Contains(message, "降智分组：可用:1个账号") || strings.Contains(message, "team 可用仅 0")) {
				t.Fatal("partial failure fabricated a shortage or lost other groups")
			}
			if tc.mode == "free-pages" && !strings.Contains(message, "free分组：可用:2个账号") {
				t.Fatal("report truncated free account pages")
			}
			if strings.Contains(message, server.URL) || strings.Contains(message, "private-password") || strings.Contains(message, "secret-session") {
				t.Fatal("upstream credentials exposed")
			}
			status := store.SubReport()
			if status.LastMessage != message || status.LastAttemptAt.IsZero() || status.LastSentAt.IsZero() != (tc.mode == "bark-fail") {
				t.Fatalf("delivery audit missing: %+v", status)
			}
			if !status.NextRunAt.Equal(config.NextRunAt) {
				t.Fatal("manual send changed schedule")
			}
			if tc.mode == "bark-fail" && status.LastError == "" {
				t.Fatal("delivery failure not saved")
			}
		})
	}
}

func TestSubReportAdminAuthorization(t *testing.T) {
	store := testStore(t)
	hash := sha256.Sum256([]byte("test-admin"))
	auth, err := NewAuth(hex.EncodeToString(hash[:]), make([]byte, 32), "https://monitor.example", false)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{store: store, runner: NewRunner(store, ""), auth: auth}
	issued := httptest.NewRecorder()
	claims, err := auth.issueSession(issued)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/admin/sub-report", "/api/admin/sub-report/test"} {
		method := "PUT"
		if strings.HasSuffix(path, "/test") {
			method = "POST"
		}
		for _, tc := range []struct {
			cookie, origin, csrf bool
			want                 int
		}{{false, false, false, 401}, {true, false, true, 403}, {true, true, false, 403}} {
			req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
			if tc.cookie {
				req.AddCookie(issued.Result().Cookies()[0])
			}
			if tc.origin {
				req.Header.Set("Origin", "https://monitor.example")
			}
			if tc.csrf {
				req.Header.Set("X-CSRF-Token", claims.CSRF)
			}
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, req)
			if response.Code != tc.want {
				t.Fatalf("%s authorization %d want %d", path, response.Code, tc.want)
			}
		}
	}
	request := httptest.NewRequest("PUT", "/api/admin/sub-report", strings.NewReader(`{"enabled":false,"cron_expression":"0 8-22/2 * * *","team_minimum":5,"degraded_minimum":1}`))
	request.AddCookie(issued.Result().Cookies()[0])
	request.Header.Set("Origin", "https://monitor.example")
	request.Header.Set("X-CSRF-Token", claims.CSRF)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	app.runner.reportMu.Lock()
	defer app.runner.reportMu.Unlock()
	request = httptest.NewRequest("POST", "/api/admin/sub-report/test", nil)
	request.AddCookie(issued.Result().Cookies()[0])
	request.Header.Set("Origin", "https://monitor.example")
	request.Header.Set("X-CSRF-Token", claims.CSRF)
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != 409 {
		t.Fatal("overlapping report not rejected")
	}
}
