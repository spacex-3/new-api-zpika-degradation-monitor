package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const defaultSubReportCron = "0 8-22/2 * * *"

// Reporting has its own schedule and uses the existing encrypted sub2api
// credentials and Bark endpoint. It never changes accounts or runs detections.
type SubReportSettings struct {
	Enabled         bool      `json:"enabled"`
	CronExpression  string    `json:"cron_expression"`
	TeamMinimum     int       `json:"team_minimum"`
	DegradedMinimum int       `json:"degraded_minimum"`
	NextRunAt       time.Time `json:"next_run_at,omitempty"`
	LastAttemptAt   time.Time `json:"last_attempt_at,omitempty"`
	LastSentAt      time.Time `json:"last_sent_at,omitempty"`
	LastMessage     string    `json:"last_message,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}

type SubReportInput struct {
	Enabled         bool   `json:"enabled"`
	CronExpression  string `json:"cron_expression"`
	TeamMinimum     int    `json:"team_minimum"`
	DegradedMinimum int    `json:"degraded_minimum"`
}

func (s *Store) subReportLocked() SubReportSettings {
	config := s.state.Settings.SubReport
	if config.CronExpression == "" {
		config.CronExpression = defaultSubReportCron
		config.TeamMinimum = 5
		config.DegradedMinimum = 1
	}
	return config
}

func (s *Store) SubReport() SubReportSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subReportLocked()
}

func (s *Store) SetSubReport(input SubReportInput, now time.Time) error {
	expression := strings.TrimSpace(input.CronExpression)
	if expression == "" {
		expression = defaultSubReportCron
	}
	expression, err := normalizeCronExpression(expression, 120)
	if err != nil {
		return err
	}
	if input.TeamMinimum < 0 || input.TeamMinimum > 10000 || input.DegradedMinimum < 0 || input.DegradedMinimum > 10000 {
		return errors.New("可用账号提醒阈值必须在 0 到 10000 之间")
	}
	if input.Enabled {
		config, err := s.RemediationConfig()
		if err != nil {
			return err
		}
		if config.SubURL == "" || config.SubEmail == "" || config.SubPassword == "" {
			return errors.New("请先保存 sub2api 管理凭据")
		}
		if _, ok := s.BarkURL(); !ok {
			return errors.New("请先配置 Bark 推送地址")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Settings.SubReport
	config := s.subReportLocked()
	// Saving unchanged settings must not skip a due notification.
	if input.Enabled && (!config.Enabled || config.CronExpression != expression || config.NextRunAt.IsZero()) {
		config.NextRunAt, err = nextCronRun(expression, now)
		if err != nil {
			return err
		}
	}
	if !input.Enabled {
		config.NextRunAt = time.Time{}
	}
	config.Enabled, config.CronExpression = input.Enabled, expression
	config.TeamMinimum, config.DegradedMinimum = input.TeamMinimum, input.DegradedMinimum
	s.state.Settings.SubReport = config
	if err := s.persistLocked(); err != nil {
		s.state.Settings.SubReport = previous
		return errors.New("定时报送设置保存失败")
	}
	return nil
}

// Claim and advance before sending. A crash or an uncertain Bark response never
// replays the same scheduled slot. Old missed slots are not sent in a burst.
func (s *Store) claimSubReport(now time.Time) (SubReportSettings, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.subReportLocked()
	if !config.Enabled || (!config.NextRunAt.IsZero() && config.NextRunAt.After(now)) {
		return config, false, nil
	}
	previous := s.state.Settings.SubReport
	next, err := nextCronRun(config.CronExpression, now)
	if err != nil {
		return config, false, errors.New("定时报送 Cron 无效")
	}
	// Do not send a stale daytime report at night after a service restart.
	due := !config.NextRunAt.IsZero() && now.Sub(config.NextRunAt) < time.Minute
	config.NextRunAt = next
	if due {
		config.LastAttemptAt = now
		config.LastError = "报送处理中；若服务中断，请核对是否已收到通知"
	}
	s.state.Settings.SubReport = config
	if err := s.persistLocked(); err != nil {
		s.state.Settings.SubReport = previous
		return config, false, errors.New("报送计划保存失败，未发送")
	}
	return config, due, nil
}

func (s *Store) finishSubReport(message string, sendErr error, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Settings.SubReport
	config := s.subReportLocked()
	config.LastAttemptAt = now
	config.LastMessage = message
	config.LastError = ""
	if sendErr != nil {
		config.LastError = sendErr.Error()
	} else {
		config.LastSentAt = now
	}
	s.state.Settings.SubReport = config
	if err := s.persistLocked(); err != nil {
		s.state.Settings.SubReport = previous
		return errors.New("报送结果保存失败")
	}
	return nil
}

func (r *Runner) scheduleSubReport(ctx context.Context) {
	if !r.reportMu.TryLock() {
		return
	}
	config, due, err := r.store.claimSubReport(time.Now().UTC())
	if err != nil || !due {
		r.reportMu.Unlock()
		if err != nil {
			slog.Warn("sub2api report schedule failed", "error", err)
		}
		return
	}
	go func() {
		defer r.reportMu.Unlock()
		if _, err := r.sendSubReport(ctx, config); err != nil {
			slog.Warn("sub2api report failed", "error", err)
		}
	}()
}

func (r *Runner) subReportMessage(ctx context.Context, config SubReportSettings) (string, string) {
	location := time.FixedZone("Asia/Shanghai", 8*3600)
	header := "北京时间 " + time.Now().In(location).Format("2006-01-02 15:04")
	names := []string{"team", "降智", "free"}
	var groups []subGroup
	credentials, err := r.store.RemediationConfig()
	client := r.remediationClient(credentials)
	if err == nil {
		if credentials.SubURL == "" || credentials.SubEmail == "" || credentials.SubPassword == "" {
			err = errors.New("sub2api 管理凭据尚未配置")
		} else {
			err = client.login(ctx)
		}
	}
	if err == nil {
		err = client.request(ctx, true, http.MethodGet, "/api/v1/admin/groups/all", nil, &groups)
	}
	if err != nil {
		return "⚠️ sub2api 状态读取失败", header + "\nteam分组：统计读取失败\n降智分组：统计读取失败\nfree分组：统计读取失败\n请在后台测试管理连接并检查凭据或接口。"
	}
	var alerts, lines, lowGroups []string
	for _, name := range names {
		var matches []int64
		for _, group := range groups {
			if group.Name == name && group.Platform == "openai" && group.ID > 0 {
				matches = append(matches, group.ID)
			}
		}
		if len(matches) != 1 {
			alerts = append(alerts, "⚠️ "+name+" 分组无法唯一确认，统计读取失败")
			lines = append(lines, name+"分组：统计读取失败")
			continue
		}
		stats, err := client.teamStats(ctx, matches[0])
		if err != nil {
			alerts = append(alerts, "⚠️ "+name+" 分组统计读取失败")
			lines = append(lines, name+"分组：统计读取失败")
			continue
		}
		lines = append(lines, stats.groupSummary(name))
		minimum := 0
		if name == "team" {
			minimum = config.TeamMinimum
		}
		if name == "降智" {
			minimum = config.DegradedMinimum
		}
		if stats.Available < minimum {
			lowGroups = append(lowGroups, name)
			alerts = append(alerts, fmt.Sprintf("‼️ %s 可用仅 %d 个，低于 %d 个，请及时补充账号", name, stats.Available, minimum))
		}
	}
	title := "sub2api 分组状态"
	if len(alerts) > 0 {
		title = "⚠️ sub2api 账号不足或统计异常"
	}
	if len(lowGroups) > 0 {
		title = "⚠️ sub2api 可用账号不足：" + strings.Join(lowGroups, "、")
	}
	body := header + "\n"
	if len(alerts) > 0 {
		body += strings.Join(alerts, "\n") + "\n\n"
	}
	return title, body + strings.Join(lines, "\n")
}

func (r *Runner) sendSubReport(ctx context.Context, config SubReportSettings) (string, error) {
	ctx, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	title, body := r.subReportMessage(readCtx, config)
	cancel()
	// Exactly one Bark request per scheduled slot. API read failures are also
	// reported, and unknown account counts are never represented as zeros.
	err := r.notifyContext(ctx, title, body)
	if saveErr := r.store.finishSubReport(body, err, time.Now().UTC()); saveErr != nil {
		return body, saveErr
	}
	return body, err
}

func (a *App) updateSubReport(w http.ResponseWriter, r *http.Request) {
	var input SubReportInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.store.SetSubReport(input, time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) testSubReport(w http.ResponseWriter, r *http.Request) {
	if !a.runner.reportMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "状态报送正在进行，请稍后再试"})
		return
	}
	defer a.runner.reportMu.Unlock()
	// A test uses saved thresholds even if the recurring schedule is disabled.
	body, err := a.runner.sendSubReport(r.Context(), a.store.SubReport())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": body})
}
