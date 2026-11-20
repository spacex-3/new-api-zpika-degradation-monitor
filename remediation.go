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
	"slices"
	"strconv"
	"strings"
	"time"
)

// Credentials and even internal URLs live in one authenticated, encrypted blob.
// Neither this type nor upstream responses are returned through public APIs.
type RemediationConfig struct {
	Enabled         bool   `json:"enabled"`
	SubURL          string `json:"sub_url"`
	SubEmail        string `json:"sub_email"`
	SubPassword     string `json:"sub_password"`
	NewURL          string `json:"new_url"`
	NewToken        string `json:"new_token"`
	NewUserID       int64  `json:"new_user_id"`
	FullTokenName   string `json:"full_token_name"`
	NormalTokenName string `json:"normal_token_name"`
}

type RemediationEvent struct {
	ResultID   string    `json:"result_id"`
	TargetName string    `json:"target_name"`
	LogID      int64     `json:"log_id,omitempty"`
	UsageID    int64     `json:"usage_id,omitempty"`
	AccountID  int64     `json:"account_id,omitempty"`
	RecheckID  string    `json:"recheck_id,omitempty"`
	State      string    `json:"state"`
	Message    string    `json:"message"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Store) RemediationConfig() (RemediationConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	config := RemediationConfig{FullTokenName: "鹈鹕-满血", NormalTokenName: "鹈鹕-不降智"}
	if s.state.Settings.EncryptedRemediation == "" {
		return config, nil
	}
	plain, err := s.open("settings:remediation", s.state.Settings.EncryptedRemediation)
	if err != nil {
		return config, errors.New("自动处理配置无法解密")
	}
	if err := json.Unmarshal([]byte(plain), &config); err != nil {
		return config, errors.New("自动处理配置无效")
	}
	return config, nil
}

func validateAdminURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("管理地址必须是 HTTPS 站点根地址，不能包含路径、账号或参数")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func (s *Store) SetRemediationConfig(input RemediationConfig) error {
	previous, err := s.RemediationConfig()
	if err != nil {
		return err
	}
	// A blank secret field always keeps its previous encrypted value.
	input.SubURL = firstNonEmpty(strings.TrimSpace(input.SubURL), previous.SubURL)
	input.SubEmail = firstNonEmpty(strings.TrimSpace(input.SubEmail), previous.SubEmail)
	input.SubPassword = firstNonEmpty(input.SubPassword, previous.SubPassword)
	input.NewURL = firstNonEmpty(strings.TrimSpace(input.NewURL), previous.NewURL)
	input.NewToken = firstNonEmpty(strings.TrimSpace(input.NewToken), previous.NewToken)
	if input.NewUserID == 0 {
		input.NewUserID = previous.NewUserID
	}
	input.FullTokenName = firstNonEmpty(strings.TrimSpace(input.FullTokenName), previous.FullTokenName)
	input.NormalTokenName = firstNonEmpty(strings.TrimSpace(input.NormalTokenName), previous.NormalTokenName)
	if input.SubURL != "" {
		input.SubURL, err = validateAdminURL(input.SubURL)
		if err != nil {
			return err
		}
	}
	if input.NewURL != "" {
		input.NewURL, err = validateAdminURL(input.NewURL)
		if err != nil {
			return err
		}
	}
	if input.Enabled && (input.SubURL == "" || input.SubEmail == "" || input.SubPassword == "" || input.NewURL == "" || input.NewToken == "" || input.NewUserID <= 0) {
		return errors.New("启用前请完整填写两个站点的管理凭据")
	}
	if len(input.SubEmail) > 254 || len(input.SubPassword) > 4096 || len(input.NewToken) > 4096 || len(input.FullTokenName) > 100 || len(input.NormalTokenName) > 100 {
		return errors.New("配置字段过长")
	}
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("配置编码失败")
	}
	sealed, err := s.seal("settings:remediation", string(data))
	if err != nil {
		return errors.New("配置加密失败")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.Settings.EncryptedRemediation
	s.state.Settings.EncryptedRemediation = sealed
	if err := s.persistLocked(); err != nil {
		s.state.Settings.EncryptedRemediation = old
		return errors.New("配置保存失败")
	}
	return nil
}

// Persist intent before the external mutation. Unfinished/uncertain events are
// never evicted or replayed automatically after a restart.
func (s *Store) saveRemediation(event RemediationEvent, claim bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := slices.Clone(s.state.Remediations)
	if claim {
		for _, item := range previous {
			if item.ResultID == event.ResultID || (event.AccountID > 0 && item.AccountID == event.AccountID && (item.State == "migrating" || item.State == "uncertain")) {
				return errors.New("此检测或账号已有处理记录，需要管理员核对")
			}
		}
	}
	event.UpdatedAt = time.Now().UTC()
	index := slices.IndexFunc(s.state.Remediations, func(item RemediationEvent) bool { return item.ResultID == event.ResultID })
	if index >= 0 {
		s.state.Remediations[index] = event
	} else {
		s.state.Remediations = append([]RemediationEvent{event}, s.state.Remediations...)
	}
	if len(s.state.Remediations) > 100 {
		for i := len(s.state.Remediations) - 1; i >= 100; i-- {
			if s.state.Remediations[i].State != "migrating" && s.state.Remediations[i].State != "uncertain" {
				s.state.Remediations = slices.Delete(s.state.Remediations, i, i+1)
			}
		}
	}
	if err := s.persistLocked(); err != nil {
		s.state.Remediations = previous
		return errors.New("处理记录保存失败，已停止自动操作")
	}
	return nil
}

type remediationClient struct {
	config   RemediationConfig
	http     *http.Client
	subToken string
}

func (r *Runner) remediationClient(config RemediationConfig) *remediationClient {
	client := *r.client
	client.Timeout = 45 * time.Second
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &remediationClient{config: config, http: &client}
}

func (c *remediationClient) request(ctx context.Context, sub bool, method, path string, payload, output any) error {
	base := c.config.NewURL
	if sub {
		base = c.config.SubURL
	}
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return errors.New("管理请求编码失败")
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return errors.New("管理请求创建失败")
	}
	req.Header.Set("Content-Type", "application/json")
	if sub && c.subToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.subToken)
	}
	if !sub {
		req.Header.Set("Authorization", "Bearer "+c.config.NewToken)
		req.Header.Set("New-Api-User", strconv.FormatInt(c.config.NewUserID, 10))
	}
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("管理接口连接失败或超时")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("管理接口返回 HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return errors.New("管理接口响应不完整或过大")
	}
	var envelope struct {
		Code    *int            `json:"code"`
		Success *bool           `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(data, &envelope) != nil || (sub && (envelope.Code == nil || *envelope.Code != 0)) || (!sub && (envelope.Success == nil || !*envelope.Success)) {
		return errors.New("管理接口拒绝请求或响应无效")
	}
	if output != nil {
		if bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) || json.Unmarshal(envelope.Data, output) != nil {
			return errors.New("管理接口数据无效")
		}
	}
	return nil
}

func (c *remediationClient) login(ctx context.Context) error {
	var data struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.request(ctx, true, http.MethodPost, "/api/v1/auth/login", map[string]string{"email": c.config.SubEmail, "password": c.config.SubPassword}, &data); err != nil {
		return err
	}
	if data.AccessToken == "" {
		return errors.New("sub2api 登录未返回有效会话，请检查凭据或双重验证设置")
	}
	c.subToken = data.AccessToken
	return nil
}

type subGroup struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

func (c *remediationClient) groups(ctx context.Context) (int64, int64, error) {
	var groups []subGroup
	if err := c.request(ctx, true, http.MethodGet, "/api/v1/admin/groups/all", nil, &groups); err != nil {
		return 0, 0, err
	}
	var team, degraded []int64
	for _, group := range groups {
		if group.Platform != "openai" {
			continue
		}
		if group.Name == "team" {
			team = append(team, group.ID)
		}
		if group.Name == "降智" {
			degraded = append(degraded, group.ID)
		}
	}
	if len(team) != 1 || len(degraded) != 1 || team[0] <= 0 || degraded[0] <= 0 || team[0] == degraded[0] {
		return 0, 0, errors.New("无法唯一确认 openai 的 team 和降智分组")
	}
	return team[0], degraded[0], nil
}

type newUsage struct {
	ID           int64  `json:"id"`
	CreatedAt    int64  `json:"created_at"`
	Group        string `json:"group"`
	TokenName    string `json:"token_name"`
	Model        string `json:"model_name"`
	Channel      int64  `json:"channel"`
	ChannelName  string `json:"channel_name"`
	InputTokens  int64  `json:"prompt_tokens"`
	OutputTokens int64  `json:"completion_tokens"`
}

func (c *remediationClient) matchNew(ctx context.Context, result Result) (newUsage, error) {
	tokenName := ""
	switch result.TargetName {
	case "codex-满血不降智":
		tokenName = c.config.FullTokenName
	case "codex-不降智":
		tokenName = c.config.NormalTokenName
	default:
		return newUsage{}, errors.New("此分组不参与自动处理")
	}
	if tokenName == "" || result.InputTokens <= 0 || result.OutputTokens <= 0 || result.FinishedAt.IsZero() || result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return newUsage{}, errors.New("检测的时间、token 或专用令牌名称不完整")
	}
	query := url.Values{"type": {"2"}, "group": {result.TargetName}, "token_name": {tokenName}, "model_name": {result.Model}, "start_timestamp": {strconv.FormatInt(result.FinishedAt.Add(-30*time.Second).Unix(), 10)}, "end_timestamp": {strconv.FormatInt(result.FinishedAt.Add(30*time.Second).Unix(), 10)}, "p": {"1"}, "page_size": {"100"}}
	var data struct {
		Total *int       `json:"total"`
		Items []newUsage `json:"items"`
	}
	if err := c.request(ctx, false, http.MethodGet, "/api/log/?"+query.Encode(), nil, &data); err != nil {
		return newUsage{}, err
	}
	if data.Total == nil || data.Items == nil || *data.Total != len(data.Items) || len(data.Items) >= 100 {
		return newUsage{}, errors.New("newapi 日志分页不完整，停止匹配")
	}
	var candidates []newUsage
	for _, item := range data.Items {
		delta := time.Unix(item.CreatedAt, 0).Sub(result.FinishedAt)
		if item.ID > 0 && item.Group == result.TargetName && item.TokenName == tokenName && item.Model == result.Model && item.InputTokens == result.InputTokens && item.OutputTokens == result.OutputTokens && delta.Abs() <= 30*time.Second {
			candidates = append(candidates, item)
		}
	}
	if len(candidates) != 1 {
		return newUsage{}, fmt.Errorf("newapi 请求匹配到 %d 条，未执行迁移", len(candidates))
	}
	return candidates[0], nil
}

type subUsage struct {
	ID              int64     `json:"id"`
	AccountID       int64     `json:"account_id"`
	GroupID         int64     `json:"group_id"`
	Model           string    `json:"model"`
	CreatedAt       time.Time `json:"created_at"`
	InputTokens     int64     `json:"input_tokens"`
	CacheReadTokens int64     `json:"cache_read_tokens"`
	OutputTokens    int64     `json:"output_tokens"`
}

func (c *remediationClient) matchSub(ctx context.Context, log newUsage, team int64) (subUsage, error) {
	location := time.FixedZone("Asia/Shanghai", 8*3600)
	completed := time.Unix(log.CreatedAt, 0)
	// Ascending immutable IDs keep new requests from shifting earlier pages.
	query := url.Values{"start_date": {completed.Add(-30 * time.Second).In(location).Format("2006-01-02")}, "end_date": {completed.Add(30 * time.Second).In(location).Format("2006-01-02")}, "timezone": {"Asia/Shanghai"}, "group_id": {strconv.FormatInt(team, 10)}, "model": {log.Model}, "page_size": {"1000"}, "sort_by": {"id"}, "sort_order": {"asc"}}
	var candidates []subUsage
	var lastID int64
	for page := 1; page <= 20; page++ {
		query.Set("page", strconv.Itoa(page))
		var data struct {
			Items    []subUsage `json:"items"`
			PageSize int        `json:"page_size"`
		}
		if err := c.request(ctx, true, http.MethodGet, "/api/v1/admin/usage?"+query.Encode(), nil, &data); err != nil {
			return subUsage{}, err
		}
		if data.PageSize <= 0 || data.PageSize > 1000 {
			return subUsage{}, errors.New("sub2api 分页信息不完整")
		}
		for _, item := range data.Items {
			if item.ID <= lastID {
				return subUsage{}, errors.New("sub2api 日志分页重叠或无效，停止匹配")
			}
			lastID = item.ID
			if item.AccountID > 0 && item.GroupID == team && item.Model == log.Model && item.InputTokens >= 0 && item.CacheReadTokens >= 0 && item.InputTokens+item.CacheReadTokens == log.InputTokens && item.OutputTokens == log.OutputTokens && item.CreatedAt.Sub(completed).Abs() <= 30*time.Second {
				candidates = append(candidates, item)
			}
		}
		if len(data.Items) < data.PageSize {
			if len(candidates) != 1 {
				return subUsage{}, fmt.Errorf("sub2api 请求匹配到 %d 条，未执行迁移", len(candidates))
			}
			return candidates[0], nil
		}
	}
	return subUsage{}, errors.New("sub2api 日志超过安全查询上限，未执行迁移")
}

type subAccount struct {
	ID                     int64      `json:"id"`
	Platform               string     `json:"platform"`
	GroupIDs               []int64    `json:"group_ids"`
	Status                 string     `json:"status"`
	Schedulable            bool       `json:"schedulable"`
	RateLimitResetAt       *time.Time `json:"rate_limit_reset_at"`
	OverloadUntil          *time.Time `json:"overload_until"`
	TempUnschedulableUntil *time.Time `json:"temp_unschedulable_until"`
	ExpiresAt              *int64     `json:"expires_at"`
}

func (c *remediationClient) account(ctx context.Context, id int64) (subAccount, error) {
	var account subAccount
	err := c.request(ctx, true, http.MethodGet, "/api/v1/admin/accounts/"+strconv.FormatInt(id, 10), nil, &account)
	if err == nil && (account.ID != id || account.Platform != "openai" || account.GroupIDs == nil) {
		err = errors.New("账号身份或分组数据不完整")
	}
	return account, err
}

type teamStats struct{ Available, RateLimited, Other, Total int }

func (s teamStats) String() string {
	text := fmt.Sprintf("team分组：可用:%d个账号，限流:%d个账号，总量:%d个账号", s.Available, s.RateLimited, s.Total)
	if s.Other > 0 {
		text += fmt.Sprintf("，其他不可用:%d个账号", s.Other)
	}
	return text
}

func (s *teamStats) count(account subAccount, now time.Time) {
	s.Total++
	// Mutually exclusive buckets, including disabled/error/expired accounts.
	active := account.Status == "active" && (account.ExpiresAt == nil || *account.ExpiresAt > now.Unix())
	if active && account.RateLimitResetAt != nil && account.RateLimitResetAt.After(now) {
		s.RateLimited++
		return
	}
	if active && account.Schedulable && (account.OverloadUntil == nil || !account.OverloadUntil.After(now)) && (account.TempUnschedulableUntil == nil || !account.TempUnschedulableUntil.After(now)) {
		s.Available++
		return
	}
	s.Other++
}

func (c *remediationClient) teamStats(ctx context.Context, team int64) (teamStats, error) {
	stats := teamStats{}
	seen := map[int64]bool{}
	now := time.Now()
	for page := 1; page <= 20; page++ {
		query := url.Values{"group": {strconv.FormatInt(team, 10)}, "platform": {"openai"}, "lite": {"true"}, "page": {strconv.Itoa(page)}, "page_size": {"1000"}}
		var data struct {
			Items    []subAccount `json:"items"`
			Total    *int         `json:"total"`
			PageSize int          `json:"page_size"`
		}
		if err := c.request(ctx, true, http.MethodGet, "/api/v1/admin/accounts?"+query.Encode(), nil, &data); err != nil {
			return teamStats{}, err
		}
		if data.Items == nil || data.PageSize <= 0 || data.Total == nil || *data.Total < 0 {
			return teamStats{}, errors.New("team 账号统计数据缺失")
		}
		for _, account := range data.Items {
			if account.ID <= 0 || seen[account.ID] || account.Platform != "openai" || !slices.Contains(account.GroupIDs, team) {
				return teamStats{}, errors.New("team 账号列表不完整")
			}
			seen[account.ID] = true
			stats.count(account, now)
		}
		if stats.Total == *data.Total {
			return stats, nil
		}
		if *data.Total < stats.Total || len(data.Items) < data.PageSize {
			return teamStats{}, errors.New("team 账号分页不完整")
		}
	}
	return teamStats{}, errors.New("team 账号数量超过安全查询上限")
}

func degradedQuality(quality string) bool {
	return quality == "degraded" || quality == "suspicious" || quality == "incorrect"
}

func (r *Runner) remediate(ctx context.Context, result Result) {
	if result.Status != "succeeded" || !degradedQuality(result.Quality) || (result.TargetName != "codex-满血不降智" && result.TargetName != "codex-不降智") {
		return
	}
	// Serialize matching + migration across monitor targets. Rechecks remain
	// outside this lock and runDetection never calls remediate recursively.
	r.remediationMu.Lock()
	config, err := r.store.RemediationConfig()
	if err != nil || !config.Enabled {
		r.remediationMu.Unlock()
		return
	}
	client := r.remediationClient(config)
	event := RemediationEvent{ResultID: result.ID, TargetName: result.TargetName, State: "checking"}
	if err := r.store.saveRemediation(event, true); err != nil {
		r.remediationMu.Unlock()
		slog.Warn("remediation claim rejected", "result_id", result.ID)
		return
	}
	matchCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	team, migrated, processErr := r.migrateAccount(matchCtx, client, result, &event)
	cancel()
	r.remediationMu.Unlock()
	if processErr != nil {
		event.Message = processErr.Error()
		if event.State != "uncertain" {
			event.State = "skipped"
		}
	}
	if migrated {
		event.State = "rechecking"
		event.Message = fmt.Sprintf("账号 #%d 已从 team 迁移至降智，等待分组复检", event.AccountID)
		if err := r.store.saveRemediation(event, false); err != nil {
			event.Message = "账号已迁移，但处理记录保存失败，未启动复检"
		} else {
			recheck, recheckErr := r.runDetection(ctx, result.TargetID, false, false)
			event.RecheckID = recheck.ID
			event.State = "completed"
			switch {
			case recheckErr != nil:
				event.Message = "账号已迁移；分组复检连续请求失败，请管理员检查"
			case degradedQuality(recheck.Quality):
				event.Message = "账号已迁移；分组复检仍疑似降智，本轮不再迁移其他账号"
			case recheck.Quality == "normal" || recheck.Quality == "passed":
				event.Message = "账号已迁移；分组复检正常（不代表原渠道或该账号已恢复）"
			default:
				event.Message = "账号已迁移；分组复检结果无法判定，请管理员查看"
			}
		}
	}
	statsText := "team分组：统计读取失败"
	// A failed initial login must not trigger another credential attempt.
	if client.subToken != "" {
		if team == 0 {
			team, _, _ = client.groups(ctx)
		}
		if team > 0 {
			if stats, err := client.teamStats(ctx, team); err == nil {
				statsText = stats.String()
			}
		}
	}
	event.Message += "\n" + statsText
	if err := r.store.saveRemediation(event, false); err != nil {
		slog.Error("remediation audit save failed", "result_id", result.ID)
	}
	body := result.TargetName + "：" + event.Message
	if event.AccountID > 0 {
		body = fmt.Sprintf("%s\n账号 #%d\n%s", result.TargetName, event.AccountID, event.Message)
	}
	if err := r.notify("降智自动处理结果", body); err != nil {
		slog.Warn("remediation bark failed", "result_id", result.ID)
	}
}

func (r *Runner) migrateAccount(ctx context.Context, c *remediationClient, result Result, event *RemediationEvent) (int64, bool, error) {
	// Authenticate once per workflow. Tokens stay in memory and are not logged.
	if err := c.login(ctx); err != nil {
		return 0, false, err
	}
	team, degraded, err := c.groups(ctx)
	if err != nil {
		return 0, false, err
	}
	log, err := c.matchNew(ctx, result)
	if err != nil {
		return team, false, err
	}
	event.LogID = log.ID
	if log.Channel != 23 || log.ChannelName != "sub2api_pro" {
		return team, false, fmt.Errorf("实际请求使用渠道 #%d，未命中 #23 sub2api_pro，未执行迁移", log.Channel)
	}
	usage, err := c.matchSub(ctx, log, team)
	if err != nil {
		return team, false, err
	}
	event.UsageID = usage.ID
	event.AccountID = usage.AccountID
	account, err := c.account(ctx, usage.AccountID)
	if err != nil {
		return team, false, err
	}
	if !slices.Contains(account.GroupIDs, team) || slices.Contains(account.GroupIDs, degraded) {
		return team, false, errors.New("账号当前已不在 team 或已属于降智分组，未执行迁移")
	}
	groups := slices.Clone(account.GroupIDs)
	groups = slices.DeleteFunc(groups, func(id int64) bool { return id == team })
	groups = append(groups, degraded)
	event.State = "migrating"
	event.Message = "已记录迁移意图；若服务中断，请管理员核对账号分组"
	// Check pending claims on this account before making any external write.
	r.store.mu.RLock()
	blocked := slices.ContainsFunc(r.store.state.Remediations, func(item RemediationEvent) bool {
		return item.ResultID != event.ResultID && item.AccountID == event.AccountID && (item.State == "migrating" || item.State == "uncertain")
	})
	r.store.mu.RUnlock()
	if blocked {
		return team, false, errors.New("该账号有未确认的迁移记录，请管理员核对")
	}
	if err := r.store.saveRemediation(*event, false); err != nil {
		return team, false, err
	}
	// Never retry a PUT after a timeout. A fresh GET determines whether it took
	// effect; any uncertainty remains recorded and blocks another migration.
	writeErr := c.request(ctx, true, http.MethodPut, "/api/v1/admin/accounts/"+strconv.FormatInt(account.ID, 10), map[string]any{"group_ids": groups}, nil)
	verified, readErr := c.account(ctx, account.ID)
	if readErr != nil || slices.Contains(verified.GroupIDs, team) || !slices.Contains(verified.GroupIDs, degraded) || !sameGroupIDs(groups, verified.GroupIDs) {
		event.State = "uncertain"
		return team, false, errors.New("迁移结果未能确认，未重试写入；请管理员检查账号和处理记录")
	}
	if writeErr != nil {
		slog.Info("account migration verified after failed response", "account_id", account.ID)
	}
	return team, true, nil
}

func sameGroupIDs(a, b []int64) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (a *App) updateRemediation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RemediationConfig
		AdminToken string `json:"admin_token"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	// Reauthentication is required to change stored administrator credentials or
	// authorize future account migrations. Reuse login throttling, not a new flow.
	if !a.auth.allowLogin(r) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "验证尝试过多，请稍后再试"})
		return
	}
	if !a.auth.validAdminToken(input.AdminToken) {
		slog.Warn("remediation configuration reauthentication rejected")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "请重新输入检测后台管理员口令"})
		return
	}
	a.auth.clearAttempts(r)
	if err := a.store.SetRemediationConfig(input.RemediationConfig); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	slog.Info("remediation configuration updated", "enabled", input.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) remediationStatus(w http.ResponseWriter, r *http.Request) {
	config, err := a.store.RemediationConfig()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": config.Enabled, "configured": config.SubURL != "" && config.NewToken != "", "full_token_name": config.FullTokenName, "normal_token_name": config.NormalTokenName, "new_user_id": config.NewUserID})
}

func (a *App) testRemediation(w http.ResponseWriter, r *http.Request) {
	config, err := a.store.RemediationConfig()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	// Read-only: no detections or account writes, including when disabled.
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	client := a.runner.remediationClient(config)
	if err = client.login(ctx); err == nil {
		var team int64
		team, _, err = client.groups(ctx)
		if err == nil {
			var stats teamStats
			stats, err = client.teamStats(ctx, team)
			if err == nil {
				// Verify newapi administrator log access without returning any logs.
				var data struct {
					Items []newUsage `json:"items"`
				}
				err = client.request(ctx, false, http.MethodGet, "/api/log/?type=2&p=1&page_size=1", nil, &data)
				if err == nil {
					writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "两个管理接口连接正常；" + stats.String()})
					return
				}
			}
		}
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
}
