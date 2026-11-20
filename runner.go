package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Runner struct {
	store         *Store
	client        *http.Client
	manxueBase    string
	pollInterval  time.Duration
	retryDelay    time.Duration
	maxAttempts   int
	mu            sync.Mutex
	running       map[string]bool
	remediationMu sync.Mutex
}

type testCreateResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Phase     string `json:"phase"`
	ExpiresAt string `json:"expires_at"`
}

type testResponse struct {
	ID              string `json:"id"`
	Benchmark       string `json:"benchmark"`
	Status          string `json:"status"`
	Phase           string `json:"phase"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
	ServiceTier     string `json:"service_tier"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	DurationMS      int64  `json:"duration_ms"`
	InputTokens     int64  `json:"input_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	ReasoningTokens int64  `json:"reasoning_tokens"`
	Error           any    `json:"error"`
	Result          struct {
		HTML            string `json:"html"`
		DurationMS      int64  `json:"duration_ms"`
		InputTokens     int64  `json:"input_tokens"`
		OutputTokens    int64  `json:"output_tokens"`
		ReasoningTokens int64  `json:"reasoning_tokens"`
		StartedAt       string `json:"started_at"`
		FinishedAt      string `json:"finished_at"`
	} `json:"result"`
	Assessment struct {
		Quality string `json:"quality"`
		Label   string `json:"label"`
		Reason  string `json:"reason"`
	} `json:"assessment"`
	Candy struct {
		Status          string `json:"status"`
		Answer          string `json:"answer"`
		DurationMS      int64  `json:"duration_ms"`
		InputTokens     int64  `json:"input_tokens"`
		OutputTokens    int64  `json:"output_tokens"`
		ReasoningTokens int64  `json:"reasoning_tokens"`
		StartedAt       string `json:"started_at"`
		FinishedAt      string `json:"finished_at"`
	} `json:"candy"`
}

type modelListResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func NewRunner(store *Store, manxueBase string) *Runner {
	return &Runner{
		store: store, manxueBase: strings.TrimRight(manxueBase, "/"),
		client: &http.Client{Timeout: 45 * time.Second}, pollInterval: 5 * time.Second,
		retryDelay: 30 * time.Second, maxAttempts: 3,
		running: map[string]bool{},
	}
}

func (r *Runner) RunningSnapshot() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string]bool, len(r.running))
	for id, running := range r.running {
		result[id] = running
	}
	return result
}

func (r *Runner) RunNow(targetID string) bool {
	r.mu.Lock()
	if r.running[targetID] {
		r.mu.Unlock()
		return false
	}
	r.running[targetID] = true
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.running, targetID)
			r.mu.Unlock()
		}()
		if err := r.run(context.Background(), targetID); err != nil {
			slog.Error("monitor run failed", "target_id", targetID, "error", err)
		}
	}()
	return true
}

func (r *Runner) StartScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			r.scheduleDue()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (r *Runner) scheduleDue() {
	for _, target := range r.store.DueTargets(time.Now().UTC()) {
		r.RunNow(target.ID)
	}
}

func (r *Runner) ListModels(ctx context.Context, targetID, suppliedKey string) ([]string, error) {
	baseURL, apiKey, err := r.store.ModelCredentials(targetID, suppliedKey)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return nil, errors.New("无法创建模型列表请求")
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Accept", "application/json")
	client := *r.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("无法连接上游模型接口")
	}
	modelsResponse, err := decodeResponse[modelListResponse](response, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("上游模型接口返回错误（HTTP %d）", response.StatusCode)
	}
	seen := make(map[string]struct{}, len(modelsResponse.Data))
	models := make([]string, 0, len(modelsResponse.Data))
	for _, model := range modelsResponse.Data {
		id := strings.TrimSpace(model.ID)
		if id == "" || len(id) > 200 || strings.ContainsFunc(id, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, id)
		if len(models) == 5000 {
			break
		}
	}
	slices.Sort(models)
	if len(models) == 0 {
		return nil, errors.New("上游未返回可用模型")
	}
	return models, nil
}

func (r *Runner) run(ctx context.Context, targetID string) error {
	result, err := r.runDetection(ctx, targetID, true, true)
	if err == nil {
		r.remediate(ctx, result)
	}
	return err
}

func (r *Runner) runDetection(ctx context.Context, targetID string, schedule, notify bool) (Result, error) {
	target, baseURL, apiKey, err := r.store.TargetSecrets(targetID)
	if err != nil {
		return Result{}, err
	}
	started := time.Now().UTC()
	if schedule {
		if err := r.store.ScheduleNext(targetID, started); err != nil {
			return Result{}, err
		}
	}
	result := Result{
		TargetID: target.ID, TargetName: target.Name,
		Benchmark: target.Benchmark, Model: target.Model,
		ReasoningEffort: target.ReasoningEffort, ServiceTier: target.ServiceTier,
		Status: "running", StartedAt: started,
	}
	var failureDetail string
	for attempt := 1; attempt <= r.maxAttempts; attempt++ {
		resultID, idErr := randomID("result_")
		if idErr != nil {
			return Result{}, idErr
		}
		result.ID = resultID
		result.StartedAt = time.Now().UTC()
		response, attemptErr := r.runAttempt(ctx, target, baseURL, apiKey, resultID)
		if attemptErr == nil && response.Status == "succeeded" {
			result.AttemptCount = attempt
			if err := r.finishResult(result, response); err != nil {
				return Result{}, err
			}
			result, _ = r.store.Result(result.ID)
			if notify {
				r.notifyResult(result, response)
			}
			return result, nil
		}
		if attemptErr != nil {
			failureDetail = sanitizeFailureDetail(attemptErr.Error(), baseURL, apiKey)
		} else {
			failureDetail = describeUpstreamError(response.Error, baseURL, apiKey)
			if failureDetail == "" {
				failureDetail = "检测服务返回失败，但未提供具体原因"
			}
		}
		if attempt < r.maxAttempts {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(r.retryDelay):
			}
		}
	}
	result.AttemptCount = r.maxAttempts
	result.StartedAt = started
	if err := r.finishFailure(result, "请求失败", failureDetail); err != nil {
		return Result{}, err
	}
	if notify {
		if err := r.notify("连续 3 次请求失败", target.Name+"：连续 3 次请求均失败，请登录后台查看原因"); err != nil {
			slog.Warn("bark notification failed", "error", err)
		}
	}
	result, _ = r.store.Result(result.ID)
	return result, errors.New(failureDetail)
}

func (r *Runner) runAttempt(ctx context.Context, target Target, baseURL, apiKey, resultID string) (testResponse, error) {
	payload := map[string]any{
		"benchmark": target.Benchmark, "base_url": baseURL, "api_key": apiKey,
		"model": target.Model, "reasoning_effort": target.ReasoningEffort,
	}
	if target.ServiceTier != "" {
		payload["service_tier"] = target.ServiceTier
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return testResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.manxueBase+"/api/v1/tests", bytes.NewReader(body))
	if err != nil {
		return testResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", resultID)
	response, err := r.client.Do(req)
	if err != nil {
		return testResponse{}, errors.New("无法连接检测服务")
	}
	created, err := decodeResponse[testCreateResponse](response, 1<<20)
	if err != nil {
		return testResponse{}, errors.New(genericHTTPError(response.StatusCode))
	}
	if created.ID == "" {
		return testResponse{}, errors.New("检测服务未返回任务编号")
	}

	pollCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	for {
		select {
		case <-pollCtx.Done():
			return testResponse{}, errors.New("检测等待超时")
		case <-time.After(r.pollInterval):
		}
		pollReq, err := http.NewRequestWithContext(pollCtx, http.MethodGet, r.manxueBase+"/api/v1/tests/"+created.ID, nil)
		if err != nil {
			return testResponse{}, errors.New("无法创建检测查询")
		}
		pollResponse, err := r.client.Do(pollReq)
		if err != nil {
			continue
		}
		current, err := decodeResponse[testResponse](pollResponse, 12<<20)
		if err != nil {
			if pollResponse.StatusCode == http.StatusTooManyRequests || pollResponse.StatusCode == http.StatusServiceUnavailable {
				continue
			}
			return testResponse{}, errors.New(genericHTTPError(pollResponse.StatusCode))
		}
		if current.Status == "running" || current.Status == "pending" || (current.Phase != "complete" && current.Status != "succeeded" && current.Status != "failed") {
			continue
		}
		return current, nil
	}
}

var sensitiveFailurePattern = regexp.MustCompile(`(?i)(https?://[^\s"']+|bearer\s+[^\s"']+|sk-[a-z0-9_-]{8,}|api[_ -]?key\s*[:=]\s*[^\s,;]+)`)

func sanitizeFailureDetail(detail string, secrets ...string) string {
	detail = strings.TrimSpace(detail)
	for _, secret := range secrets {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, "[敏感信息已隐藏]")
		}
	}
	detail = sensitiveFailurePattern.ReplaceAllString(detail, "[敏感信息已隐藏]")
	runes := []rune(detail)
	if len(runes) > 500 {
		detail = string(runes[:500]) + "..."
	}
	return detail
}

func describeUpstreamError(value any, secrets ...string) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return sanitizeFailureDetail(text, secrets...)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "检测服务返回了无法解析的失败原因"
	}
	return sanitizeFailureDetail(string(encoded), secrets...)
}

func decodeResponse[T any](response *http.Response, maxBytes int64) (T, error) {
	var zero T
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return zero, fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxBytes))
	var result T
	if err := decoder.Decode(&result); err != nil {
		return zero, err
	}
	return result, nil
}

func genericHTTPError(status int) string {
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		return "检测服务繁忙，请稍后重试"
	}
	return fmt.Sprintf("检测服务返回错误（HTTP %d）", status)
}

func parseTime(value string, fallback time.Time) time.Time {
	if value == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return fallback
	}
	return parsed.UTC()
}

func (r *Runner) finishResult(result Result, response testResponse) error {
	result.FinishedAt = time.Now().UTC()
	result.StartedAt = parseTime(response.StartedAt, result.StartedAt)
	result.FinishedAt = parseTime(response.FinishedAt, result.FinishedAt)
	result.Status = response.Status
	if result.Status == "" {
		result.Status = "failed"
	}
	result.Model = firstNonEmpty(response.Model, result.Model)
	result.ReasoningEffort = firstNonEmpty(response.ReasoningEffort, result.ReasoningEffort)
	result.ServiceTier = firstNonEmpty(response.ServiceTier, result.ServiceTier)
	result.DurationMS = response.DurationMS
	result.InputTokens = response.InputTokens
	result.OutputTokens = response.OutputTokens
	result.ReasoningTokens = response.ReasoningTokens
	result.Quality = response.Assessment.Quality
	result.Label = response.Assessment.Label
	result.Reason = response.Assessment.Reason
	html := response.Result.HTML
	if result.Benchmark == "candy" {
		result.Quality = response.Candy.Status
		result.Label = candyLabel(response.Candy.Status)
		result.Answer = response.Candy.Answer
		result.DurationMS = response.Candy.DurationMS
		result.InputTokens = response.Candy.InputTokens
		result.OutputTokens = response.Candy.OutputTokens
		result.ReasoningTokens = response.Candy.ReasoningTokens
		result.StartedAt = parseTime(response.Candy.StartedAt, result.StartedAt)
		result.FinishedAt = parseTime(response.Candy.FinishedAt, result.FinishedAt)
	} else {
		if response.Result.DurationMS > 0 {
			result.DurationMS = response.Result.DurationMS
		}
		if response.Result.InputTokens > 0 {
			result.InputTokens = response.Result.InputTokens
		}
		if response.Result.OutputTokens > 0 {
			result.OutputTokens = response.Result.OutputTokens
		}
		if response.Result.ReasoningTokens > 0 {
			result.ReasoningTokens = response.Result.ReasoningTokens
		}
		result.StartedAt = parseTime(response.Result.StartedAt, result.StartedAt)
		result.FinishedAt = parseTime(response.Result.FinishedAt, result.FinishedAt)
	}
	return r.store.AddResult(result, html)
}

func (r *Runner) finishFailure(result Result, message, detail string) error {
	result.Status = "failed"
	result.Error = message
	result.FailureDetail = detail
	result.FinishedAt = time.Now().UTC()
	result.DurationMS = result.FinishedAt.Sub(result.StartedAt).Milliseconds()
	if err := r.store.AddResult(result, ""); err != nil {
		return err
	}
	return nil
}

func (r *Runner) notifyResult(result Result, response testResponse) {
	quality := response.Assessment.Quality
	label := response.Assessment.Label
	if result.Benchmark == "candy" {
		quality = response.Candy.Status
		label = candyLabel(quality)
	}
	degraded := quality == "degraded" || quality == "suspicious" || quality == "incorrect"
	if !degraded && !r.store.NotifyAll() {
		return
	}
	if label == "" {
		label = quality
	}
	title := "检测正常"
	if degraded {
		title = "检测到疑似降智"
	}
	if err := r.notify(title, result.TargetName+"："+label); err != nil {
		slog.Warn("bark notification failed", "error", err)
	}
}

func (r *Runner) TestNotification() error {
	return r.notify("降智检测测试", "检测服务与 Bark 连接正常")
}

func (r *Runner) notify(title, body string) error {
	barkURL, ok := r.store.BarkURL()
	if !ok {
		return errors.New("尚未配置 Bark 地址")
	}
	endpoint := strings.TrimRight(barkURL, "/") + "/" + url.PathEscape(title) + "/" + url.PathEscape(sanitizeFailureDetail(body))
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("Bark 地址无效")
	}
	query := request.URL.Query()
	query.Set("group", "降智检测")
	query.Set("isArchive", strconv.Itoa(1))
	request.URL.RawQuery = query.Encode()
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("无法连接 Bark 服务")
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Bark 返回 HTTP %d", response.StatusCode)
	}
	var result struct {
		Code int `json:"code"`
	}
	if len(responseBody) > 0 && json.Unmarshal(responseBody, &result) == nil && result.Code != 0 && result.Code != 200 {
		return errors.New("Bark 拒绝了测试通知")
	}
	return nil
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func candyLabel(status string) string {
	switch status {
	case "passed":
		return "通过"
	case "incorrect":
		return "未通过"
	case "error":
		return "检测异常"
	default:
		return status
	}
}
