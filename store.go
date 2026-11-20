package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

const stateVersion = 1

type Settings struct {
	EncryptedBaseURL  string `json:"encrypted_base_url,omitempty"`
	BaseURLConfigured bool   `json:"base_url_configured"`
	EncryptedBarkURL  string `json:"encrypted_bark_url,omitempty"`
	BarkConfigured    bool   `json:"bark_configured"`
	NotifyAll         bool   `json:"notify_all,omitempty"`
}

type Target struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	DisplayOrder     int       `json:"display_order,omitempty"`
	Benchmark        string    `json:"benchmark"`
	Model            string    `json:"model"`
	ReasoningEffort  string    `json:"reasoning_effort"`
	ServiceTier      string    `json:"service_tier,omitempty"`
	IntervalMinutes  int       `json:"interval_minutes"`
	CronExpression   string    `json:"cron_expression,omitempty"`
	RetainCount      int       `json:"retain_count"`
	Enabled          bool      `json:"enabled"`
	Hidden           bool      `json:"hidden,omitempty"`
	EncryptedAPIKey  string    `json:"encrypted_api_key,omitempty"`
	APIKeyConfigured bool      `json:"api_key_configured"`
	NextRunAt        time.Time `json:"next_run_at"`
	LastRunAt        time.Time `json:"last_run_at,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type Result struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"target_id"`
	TargetName      string    `json:"target_name"`
	Benchmark       string    `json:"benchmark"`
	Model           string    `json:"model"`
	ReasoningEffort string    `json:"reasoning_effort"`
	ServiceTier     string    `json:"service_tier,omitempty"`
	Status          string    `json:"status"`
	Quality         string    `json:"quality,omitempty"`
	Label           string    `json:"label,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	Error           string    `json:"error,omitempty"`
	FailureDetail   string    `json:"failure_detail,omitempty"`
	AttemptCount    int       `json:"attempt_count,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	InputTokens     int64     `json:"input_tokens,omitempty"`
	OutputTokens    int64     `json:"output_tokens,omitempty"`
	ReasoningTokens int64     `json:"reasoning_tokens,omitempty"`
	Answer          string    `json:"answer,omitempty"`
	ArtifactFile    string    `json:"artifact_file,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

type persistedState struct {
	Version  int            `json:"version"`
	Settings Settings       `json:"settings"`
	Targets  []Target       `json:"targets"`
	Results  []Result       `json:"results"`
	History  []HistoryEntry `json:"history,omitempty"`
}

type HistoryEntry struct {
	ID           string    `json:"id"`
	TargetID     string    `json:"target_id"`
	TargetName   string    `json:"target_name"`
	Status       string    `json:"status"`
	Quality      string    `json:"quality,omitempty"`
	Label        string    `json:"label,omitempty"`
	DurationMS   int64     `json:"duration_ms,omitempty"`
	InputTokens  int64     `json:"input_tokens,omitempty"`
	OutputTokens int64     `json:"output_tokens,omitempty"`
	AttemptCount int       `json:"attempt_count,omitempty"`
	FinishedAt   time.Time `json:"finished_at"`
}

const maxHistoryEntries = 60

type Store struct {
	mu          sync.RWMutex
	dataDir     string
	statePath   string
	artifactDir string
	key         []byte
	state       persistedState
}

type TargetInput struct {
	Name            string `json:"name"`
	Benchmark       string `json:"benchmark"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
	ServiceTier     string `json:"service_tier"`
	IntervalMinutes int    `json:"interval_minutes"`
	CronExpression  string `json:"cron_expression"`
	RetainCount     int    `json:"retain_count"`
	Enabled         bool   `json:"enabled"`
	PublicVisible   *bool  `json:"public_visible"`
	APIKey          string `json:"api_key"`
}

func NewStore(dataDir string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	artifactDir := filepath.Join(dataDir, "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	store := &Store{
		dataDir:     dataDir,
		statePath:   filepath.Join(dataDir, "state.json"),
		artifactDir: artifactDir,
		key:         slices.Clone(key),
		state: persistedState{
			Version: stateVersion,
			Targets: []Target{},
			Results: []Result{},
		},
	}
	data, err := os.ReadFile(store.statePath)
	if errors.Is(err, os.ErrNotExist) {
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if store.state.Version != stateVersion {
		return nil, fmt.Errorf("unsupported state version %d", store.state.Version)
	}
	migrated := false
	if normalizeTargetDisplayOrder(store.state.Targets) {
		migrated = true
	}
	now := time.Now().UTC()
	for i := range store.state.Targets {
		if store.state.Targets[i].CronExpression != "" {
			continue
		}
		store.state.Targets[i].CronExpression = legacyCronExpression(store.state.Targets[i].IntervalMinutes)
		next, err := nextCronRun(store.state.Targets[i].CronExpression, now)
		if err != nil {
			return nil, fmt.Errorf("migrate target schedule: %w", err)
		}
		store.state.Targets[i].NextRunAt = next
		migrated = true
	}
	if migrated {
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
	}
	if len(store.state.History) == 0 && len(store.state.Results) > 0 {
		for i := len(store.state.Results) - 1; i >= 0; i-- {
			store.state.History = appendHistory(store.state.History, historyEntry(store.state.Results[i]))
		}
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
	} else if len(store.state.History) > 0 {
		resultsByID := make(map[string]Result, len(store.state.Results))
		for _, result := range store.state.Results {
			resultsByID[result.ID] = result
		}
		enriched := false
		for i := range store.state.History {
			result, ok := resultsByID[store.state.History[i].ID]
			if !ok || store.state.History[i].DurationMS != 0 {
				continue
			}
			store.state.History[i] = historyEntry(result)
			enriched = true
		}
		if enriched {
			if err := store.persistLocked(); err != nil {
				return nil, err
			}
		}
	}
	return store, nil
}

var defaultTargetDisplayOrder = map[string]int{
	"gpt-官key":    1,
	"codex-满血不降智": 2,
	"codex-不降智":   3,
	"codex-特惠":    4,
}

func normalizeTargetDisplayOrder(targets []Target) bool {
	if len(targets) == 0 {
		return false
	}
	originalIDs := make([]string, len(targets))
	allUnset := true
	for i, target := range targets {
		originalIDs[i] = target.ID
		if target.DisplayOrder > 0 {
			allUnset = false
		}
	}
	slices.SortStableFunc(targets, func(left, right Target) int {
		if allUnset {
			leftOrder, leftKnown := defaultTargetDisplayOrder[left.Name]
			rightOrder, rightKnown := defaultTargetDisplayOrder[right.Name]
			switch {
			case leftKnown && rightKnown:
				return leftOrder - rightOrder
			case leftKnown:
				return -1
			case rightKnown:
				return 1
			default:
				return 0
			}
		}
		switch {
		case left.DisplayOrder > 0 && right.DisplayOrder > 0:
			return left.DisplayOrder - right.DisplayOrder
		case left.DisplayOrder > 0:
			return -1
		case right.DisplayOrder > 0:
			return 1
		default:
			return 0
		}
	})
	changed := false
	for i := range targets {
		if originalIDs[i] != targets[i].ID || targets[i].DisplayOrder != i+1 {
			changed = true
		}
		targets[i].DisplayOrder = i + 1
	}
	return changed
}

func historyEntry(result Result) HistoryEntry {
	return HistoryEntry{
		ID: result.ID, TargetID: result.TargetID, TargetName: result.TargetName,
		Status: result.Status, Quality: result.Quality, Label: result.Label,
		DurationMS: result.DurationMS, InputTokens: result.InputTokens,
		OutputTokens: result.OutputTokens, AttemptCount: result.AttemptCount,
		FinishedAt: result.FinishedAt,
	}
}

func appendHistory(history []HistoryEntry, entry HistoryEntry) []HistoryEntry {
	history = append(history, entry)
	if len(history) > maxHistoryEntries {
		history = history[len(history)-maxHistoryEntries:]
	}
	return history
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

func legacyCronExpression(minutes int) string {
	if minutes <= 0 {
		minutes = 120
	}
	if minutes < 60 && 60%minutes == 0 {
		return fmt.Sprintf("*/%d * * * *", minutes)
	}
	if minutes%60 == 0 {
		hours := minutes / 60
		if hours < 24 && 24%hours == 0 {
			return fmt.Sprintf("0 */%d * * *", hours)
		}
	}
	return fmt.Sprintf("@every %dm", minutes)
}

func normalizeCronExpression(expression string, legacyMinutes int) (string, error) {
	expression = strings.Join(strings.Fields(expression), " ")
	if expression == "" {
		expression = legacyCronExpression(legacyMinutes)
	}
	if len(strings.Fields(expression)) != 5 {
		return "", errors.New("Cron 表达式必须使用标准 5 段格式")
	}
	schedule, err := cronParser.Parse(expression)
	if err != nil {
		return "", errors.New("Cron 表达式无效")
	}
	now := time.Now().UTC()
	first := schedule.Next(now)
	second := schedule.Next(first)
	if first.IsZero() || second.IsZero() {
		return "", errors.New("Cron 表达式没有可执行时间")
	}
	if second.Sub(first) < 10*time.Minute {
		return "", errors.New("Cron 执行间隔不能少于 10 分钟")
	}
	return expression, nil
}

func nextCronRun(expression string, after time.Time) (time.Time, error) {
	schedule, err := cronParser.Parse(expression)
	if err != nil {
		return time.Time{}, err
	}
	shanghai := time.FixedZone("Asia/Shanghai", 8*60*60)
	next := schedule.Next(after.In(shanghai))
	if next.IsZero() {
		return time.Time{}, errors.New("Cron 表达式没有可执行时间")
	}
	return next.UTC(), nil
}

func cronIntervalHint(expression string) int {
	schedule, err := cronParser.Parse(expression)
	if err != nil {
		return 120
	}
	shanghai := time.FixedZone("Asia/Shanghai", 8*60*60)
	first := schedule.Next(time.Now().In(shanghai))
	second := schedule.Next(first)
	minutes := int(second.Sub(first).Minutes())
	return min(max(minutes, 10), 43200)
}

func (s *Store) seal(label, value string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(value), []byte(label))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Store) open(label, value string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("invalid encrypted value")
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("encrypted value is too short")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(label))
	if err != nil {
		return "", errors.New("cannot decrypt value")
	}
	return string(plain), nil
}

func randomID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp, err := os.CreateTemp(s.dataDir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

func normalizeTargetInput(input TargetInput, requireKey bool) (TargetInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Benchmark = strings.TrimSpace(strings.ToLower(input.Benchmark))
	input.Model = strings.TrimSpace(input.Model)
	input.ReasoningEffort = strings.TrimSpace(strings.ToLower(input.ReasoningEffort))
	input.ServiceTier = strings.TrimSpace(strings.ToLower(input.ServiceTier))
	input.APIKey = strings.TrimSpace(input.APIKey)
	var err error
	input.CronExpression, err = normalizeCronExpression(input.CronExpression, input.IntervalMinutes)
	if err != nil {
		return input, err
	}
	if input.IntervalMinutes <= 0 {
		input.IntervalMinutes = cronIntervalHint(input.CronExpression)
	}
	if input.Name == "" || len(input.Name) > 80 {
		return input, errors.New("分组名称不能为空且不能超过 80 个字符")
	}
	if !slices.Contains([]string{"pelican", "candy", "creative"}, input.Benchmark) {
		return input, errors.New("检测类型无效")
	}
	if input.Model == "" {
		input.Model = "gpt-6-astra"
	}
	if len(input.Model) > 200 || strings.ContainsFunc(input.Model, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return input, errors.New("模型名称无效或超过 200 个字符")
	}
	if !slices.Contains([]string{"low", "medium", "high"}, input.ReasoningEffort) {
		return input, errors.New("推理强度无效")
	}
	if !slices.Contains([]string{"", "priority", "ultrafast"}, input.ServiceTier) {
		return input, errors.New("服务档位无效")
	}
	if input.RetainCount < 1 || input.RetainCount > 60 {
		return input, errors.New("保留次数必须在 1 到 60 之间")
	}
	if requireKey && input.APIKey == "" {
		return input, errors.New("API Key 不能为空")
	}
	return input, nil
}

func (s *Store) SetBaseURL(baseURL string) error {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return errors.New("Base URL 不能为空")
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return errors.New("Base URL 必须使用 HTTPS")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	sealed, err := s.seal("settings:base_url", baseURL)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings.EncryptedBaseURL = sealed
	s.state.Settings.BaseURLConfigured = true
	return s.persistLocked()
}

func (s *Store) SetBarkURL(barkURL string) error {
	barkURL = strings.TrimSpace(barkURL)
	if barkURL == "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.Settings.EncryptedBarkURL = ""
		s.state.Settings.BarkConfigured = false
		return s.persistLocked()
	}
	if len(barkURL) > 1024 {
		return errors.New("Bark 地址过长")
	}
	parsed, err := url.Parse(barkURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Bark 地址必须是无查询参数的 HTTPS 地址")
	}
	sealed, err := s.seal("settings:bark_url", strings.TrimRight(barkURL, "/"))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings.EncryptedBarkURL = sealed
	s.state.Settings.BarkConfigured = true
	return s.persistLocked()
}

func (s *Store) BarkURL() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.state.Settings.BarkConfigured || s.state.Settings.EncryptedBarkURL == "" {
		return "", false
	}
	barkURL, err := s.open("settings:bark_url", s.state.Settings.EncryptedBarkURL)
	if err != nil {
		return "", false
	}
	return barkURL, true
}

func (s *Store) SetNotifyAll(notifyAll bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Settings.NotifyAll = notifyAll
	return s.persistLocked()
}

func (s *Store) NotifyAll() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Settings.NotifyAll
}

func (s *Store) AddTarget(input TargetInput) (Target, error) {
	input, err := normalizeTargetInput(input, true)
	if err != nil {
		return Target{}, err
	}
	id, err := randomID("target_")
	if err != nil {
		return Target{}, err
	}
	sealed, err := s.seal("target:"+id+":api_key", input.APIKey)
	if err != nil {
		return Target{}, err
	}
	now := time.Now().UTC()
	nextRunAt, err := nextCronRun(input.CronExpression, now)
	if err != nil {
		return Target{}, err
	}
	target := Target{
		ID:               id,
		Name:             input.Name,
		Benchmark:        input.Benchmark,
		Model:            input.Model,
		ReasoningEffort:  input.ReasoningEffort,
		ServiceTier:      input.ServiceTier,
		IntervalMinutes:  input.IntervalMinutes,
		CronExpression:   input.CronExpression,
		RetainCount:      input.RetainCount,
		Enabled:          input.Enabled,
		Hidden:           input.PublicVisible != nil && !*input.PublicVisible,
		EncryptedAPIKey:  sealed,
		APIKeyConfigured: true,
		NextRunAt:        nextRunAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target.DisplayOrder = len(s.state.Targets) + 1
	s.state.Targets = append(s.state.Targets, target)
	if err := s.persistLocked(); err != nil {
		return Target{}, err
	}
	return target, nil
}

func (s *Store) MoveTarget(id string, offset int) error {
	if offset != -1 && offset != 1 {
		return errors.New("分组移动方向无效")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i, target := range s.state.Targets {
		if target.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return os.ErrNotExist
	}
	destination := index + offset
	if destination < 0 || destination >= len(s.state.Targets) {
		return nil
	}
	s.state.Targets[index], s.state.Targets[destination] = s.state.Targets[destination], s.state.Targets[index]
	now := time.Now().UTC()
	for i := range s.state.Targets {
		s.state.Targets[i].DisplayOrder = i + 1
	}
	s.state.Targets[index].UpdatedAt = now
	s.state.Targets[destination].UpdatedAt = now
	return s.persistLocked()
}

func (s *Store) UpdateTarget(id string, input TargetInput) (Target, error) {
	input, err := normalizeTargetInput(input, false)
	if err != nil {
		return Target{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Targets {
		if s.state.Targets[i].ID != id {
			continue
		}
		target := &s.state.Targets[i]
		cronChanged := target.CronExpression != input.CronExpression
		target.Name = input.Name
		target.Benchmark = input.Benchmark
		target.Model = input.Model
		target.ReasoningEffort = input.ReasoningEffort
		target.ServiceTier = input.ServiceTier
		target.IntervalMinutes = input.IntervalMinutes
		target.CronExpression = input.CronExpression
		target.RetainCount = input.RetainCount
		target.Enabled = input.Enabled
		if input.PublicVisible != nil {
			target.Hidden = !*input.PublicVisible
		}
		target.UpdatedAt = time.Now().UTC()
		if input.APIKey != "" {
			sealed, sealErr := s.seal("target:"+id+":api_key", input.APIKey)
			if sealErr != nil {
				return Target{}, sealErr
			}
			target.EncryptedAPIKey = sealed
			target.APIKeyConfigured = true
		}
		if cronChanged || target.NextRunAt.Before(time.Now().UTC()) {
			nextRunAt, nextErr := nextCronRun(target.CronExpression, time.Now().UTC())
			if nextErr != nil {
				return Target{}, nextErr
			}
			target.NextRunAt = nextRunAt
		}
		if err := s.persistLocked(); err != nil {
			return Target{}, err
		}
		return *target, nil
	}
	return Target{}, os.ErrNotExist
}

func (s *Store) DeleteTarget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	keptTargets := s.state.Targets[:0]
	for _, target := range s.state.Targets {
		if target.ID == id {
			found = true
			continue
		}
		keptTargets = append(keptTargets, target)
	}
	if !found {
		return os.ErrNotExist
	}
	s.state.Targets = keptTargets
	keptHistory := s.state.History[:0]
	for _, entry := range s.state.History {
		if entry.TargetID != id {
			keptHistory = append(keptHistory, entry)
		}
	}
	s.state.History = keptHistory
	keptResults := s.state.Results[:0]
	for _, result := range s.state.Results {
		if result.TargetID == id {
			if result.ArtifactFile != "" {
				_ = os.Remove(filepath.Join(s.artifactDir, result.ArtifactFile))
			}
			continue
		}
		keptResults = append(keptResults, result)
	}
	s.state.Results = keptResults
	return s.persistLocked()
}

func (s *Store) AdminState(running map[string]bool) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	targets := make([]map[string]any, 0, len(s.state.Targets))
	for _, target := range s.state.Targets {
		targets = append(targets, map[string]any{
			"id": target.ID, "name": target.Name, "benchmark": target.Benchmark,
			"display_order": target.DisplayOrder,
			"model":         target.Model, "reasoning_effort": target.ReasoningEffort,
			"service_tier": target.ServiceTier, "interval_minutes": target.IntervalMinutes,
			"cron_expression": target.CronExpression,
			"retain_count":    target.RetainCount, "enabled": target.Enabled,
			"public_visible":     !target.Hidden,
			"api_key_configured": target.APIKeyConfigured, "next_run_at": target.NextRunAt,
			"last_run_at": target.LastRunAt, "running": running[target.ID],
		})
	}
	failures := make([]map[string]any, 0, 10)
	for _, result := range s.state.Results {
		if result.Status != "failed" {
			continue
		}
		detail := result.FailureDetail
		if detail == "" {
			detail = "检测服务未提供具体原因（旧记录）"
		}
		failures = append(failures, map[string]any{
			"id": result.ID, "target_name": result.TargetName,
			"finished_at": result.FinishedAt, "attempt_count": result.AttemptCount,
			"failure_detail": detail,
		})
		if len(failures) == 10 {
			break
		}
	}
	return map[string]any{
		"base_url_configured": s.state.Settings.BaseURLConfigured,
		"bark_configured":     s.state.Settings.BarkConfigured,
		"notify_all":          s.state.Settings.NotifyAll,
		"targets":             targets,
		"failures":            failures,
	}
}

func publicResult(result Result) Result {
	result.FailureDetail = ""
	if result.Status == "failed" {
		result.Error = "请求失败"
	}
	return result
}

func (s *Store) PublicState(running map[string]bool) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	targets := make([]map[string]any, 0, len(s.state.Targets))
	for _, target := range s.state.Targets {
		if !target.Enabled || target.Hidden {
			continue
		}
		targets = append(targets, map[string]any{
			"id": target.ID, "name": target.Name, "benchmark": target.Benchmark,
			"interval_minutes": target.IntervalMinutes, "next_run_at": target.NextRunAt,
			"cron_expression": target.CronExpression,
			"last_run_at":     target.LastRunAt, "running": running[target.ID],
		})
	}
	results := make([]Result, 0, len(s.state.Results))
	for _, result := range s.state.Results {
		if !s.targetPublicLocked(result.TargetID) {
			continue
		}
		copyResult := publicResult(result)
		copyResult.Answer = ""
		copyResult.ArtifactFile = ""
		results = append(results, copyResult)
	}
	history := make([]HistoryEntry, 0, len(s.state.History))
	for _, entry := range s.state.History {
		if s.targetPublicLocked(entry.TargetID) {
			history = append(history, entry)
		}
	}
	for left, right := 0, len(history)-1; left < right; left, right = left+1, right-1 {
		history[left], history[right] = history[right], history[left]
	}
	return map[string]any{"targets": targets, "results": results, "history": history}
}

func (s *Store) targetPublicLocked(id string) bool {
	for _, target := range s.state.Targets {
		if target.ID == id {
			return !target.Hidden
		}
	}
	return false
}

func (s *Store) PublicResult(id string) (Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, result := range s.state.Results {
		if result.ID == id && s.targetPublicLocked(result.TargetID) {
			return result, true
		}
	}
	return Result{}, false
}

func (s *Store) Result(id string) (Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, result := range s.state.Results {
		if result.ID == id {
			return result, true
		}
	}
	return Result{}, false
}

func (s *Store) Artifact(result Result) ([]byte, error) {
	if result.ArtifactFile == "" || filepath.Base(result.ArtifactFile) != result.ArtifactFile {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(s.artifactDir, result.ArtifactFile))
}

func (s *Store) DueTargets(now time.Time) []Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var targets []Target
	for _, target := range s.state.Targets {
		if target.Enabled && target.APIKeyConfigured && !target.NextRunAt.After(now) {
			targets = append(targets, target)
		}
	}
	return targets
}

func (s *Store) TargetSecrets(id string) (Target, string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.state.Settings.BaseURLConfigured {
		return Target{}, "", "", errors.New("Base URL 尚未配置")
	}
	baseURL, err := s.open("settings:base_url", s.state.Settings.EncryptedBaseURL)
	if err != nil {
		return Target{}, "", "", err
	}
	for _, target := range s.state.Targets {
		if target.ID != id {
			continue
		}
		apiKey, err := s.open("target:"+id+":api_key", target.EncryptedAPIKey)
		if err != nil {
			return Target{}, "", "", err
		}
		return target, baseURL, apiKey, nil
	}
	return Target{}, "", "", os.ErrNotExist
}

func (s *Store) ModelCredentials(id, suppliedKey string) (string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.state.Settings.BaseURLConfigured {
		return "", "", errors.New("Base URL 尚未配置")
	}
	baseURL, err := s.open("settings:base_url", s.state.Settings.EncryptedBaseURL)
	if err != nil {
		return "", "", err
	}
	if apiKey := strings.TrimSpace(suppliedKey); apiKey != "" {
		return baseURL, apiKey, nil
	}
	if id == "" {
		return "", "", errors.New("请先填写 API Key")
	}
	for _, target := range s.state.Targets {
		if target.ID != id {
			continue
		}
		apiKey, err := s.open("target:"+id+":api_key", target.EncryptedAPIKey)
		if err != nil {
			return "", "", err
		}
		return baseURL, apiKey, nil
	}
	return "", "", os.ErrNotExist
}

func (s *Store) ScheduleNext(id string, started time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Targets {
		if s.state.Targets[i].ID == id {
			nextRunAt, err := nextCronRun(s.state.Targets[i].CronExpression, started)
			if err != nil {
				return err
			}
			s.state.Targets[i].LastRunAt = started
			s.state.Targets[i].NextRunAt = nextRunAt
			return s.persistLocked()
		}
	}
	return os.ErrNotExist
}

func (s *Store) AddResult(result Result, html string) error {
	if html != "" {
		name := result.ID + ".html"
		path := filepath.Join(s.artifactDir, name)
		if err := os.WriteFile(path, []byte(html), 0o600); err != nil {
			return fmt.Errorf("write artifact: %w", err)
		}
		result.ArtifactFile = name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.History = appendHistory(s.state.History, historyEntry(result))
	s.state.Results = append([]Result{result}, s.state.Results...)
	retain := 6
	for _, target := range s.state.Targets {
		if target.ID == result.TargetID {
			retain = target.RetainCount
			break
		}
	}
	seen := 0
	kept := s.state.Results[:0]
	for _, item := range s.state.Results {
		if item.TargetID != result.TargetID {
			kept = append(kept, item)
			continue
		}
		seen++
		if seen <= retain {
			kept = append(kept, item)
			continue
		}
		if item.ArtifactFile != "" {
			_ = os.Remove(filepath.Join(s.artifactDir, item.ArtifactFile))
		}
	}
	s.state.Results = kept
	return s.persistLocked()
}
