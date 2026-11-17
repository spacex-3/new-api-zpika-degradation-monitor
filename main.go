package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type App struct {
	store              *Store
	auth               *Auth
	runner             *Runner
	allowedHost        string
	embedParentOrigins []string
	static             http.Handler
}

type appConfig struct {
	ListenAddr         string
	DataDir            string
	AllowedHost        string
	PublicOrigin       string
	ManxueBaseURL      string
	TrustCloudflare    bool
	EncryptionKeyFile  string
	SessionKeyFile     string
	AdminHashFile      string
	BootstrapURLFile   string
	EmbedParentOrigins string
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func loadConfig() appConfig {
	return appConfig{
		ListenAddr:         envOrDefault("LISTEN_ADDR", ":8080"),
		DataDir:            envOrDefault("DATA_DIR", "/data"),
		AllowedHost:        envOrDefault("ALLOWED_HOST", "localhost"),
		PublicOrigin:       envOrDefault("PUBLIC_ORIGIN", "http://localhost:8080"),
		ManxueBaseURL:      envOrDefault("MANXUE_BASE_URL", "https://manxue.ai"),
		TrustCloudflare:    envOrDefault("TRUST_CLOUDFLARE", "false") == "true",
		EncryptionKeyFile:  envOrDefault("ENCRYPTION_KEY_FILE", "/run/secrets/encryption_key"),
		SessionKeyFile:     envOrDefault("SESSION_KEY_FILE", "/run/secrets/session_key"),
		AdminHashFile:      envOrDefault("ADMIN_TOKEN_HASH_FILE", "/run/secrets/admin_token_hash"),
		BootstrapURLFile:   envOrDefault("BOOTSTRAP_BASE_URL_FILE", "/run/secrets/bootstrap_base_url"),
		EmbedParentOrigins: strings.TrimSpace(os.Getenv("EMBED_PARENT_ORIGINS")),
	}
}

func parseEmbedParentOrigins(value string) ([]string, error) {
	var origins []string
	for raw := range strings.SplitSeq(value, ",") {
		origin := strings.TrimRight(strings.TrimSpace(raw), "/")
		if origin == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid embed parent origin %q", origin)
		}
		origins = append(origins, origin)
	}
	return origins, nil
}

func readSecret(path string, decodeBase64 bool) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if !decodeBase64 {
		return data, nil
	}
	decoded, err := base64.RawStdEncoding.DecodeString(string(data))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(string(data))
	}
	if err != nil {
		return nil, fmt.Errorf("decode secret %s: %w", path, err)
	}
	return decoded, nil
}

func newApp(config appConfig) (*App, error) {
	encryptionKey, err := readSecret(config.EncryptionKeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("load encryption key: %w", err)
	}
	sessionKey, err := readSecret(config.SessionKeyFile, true)
	if err != nil {
		return nil, fmt.Errorf("load session key: %w", err)
	}
	adminHash, err := readSecret(config.AdminHashFile, false)
	if err != nil {
		return nil, fmt.Errorf("load admin token hash: %w", err)
	}
	store, err := NewStore(config.DataDir, encryptionKey)
	if err != nil {
		return nil, err
	}
	if !store.state.Settings.BaseURLConfigured {
		if bootstrapURL, readErr := readSecret(config.BootstrapURLFile, false); readErr == nil && len(bootstrapURL) > 0 {
			if err := store.SetBaseURL(string(bootstrapURL)); err != nil {
				return nil, fmt.Errorf("bootstrap Base URL: %w", err)
			}
		}
	}
	auth, err := NewAuth(string(adminHash), sessionKey, config.PublicOrigin, config.TrustCloudflare)
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		return nil, err
	}
	embedParentOrigins, err := parseEmbedParentOrigins(config.EmbedParentOrigins)
	if err != nil {
		return nil, err
	}
	return &App{
		store: store, auth: auth, runner: NewRunner(store, config.ManxueBaseURL),
		allowedHost: config.AllowedHost, embedParentOrigins: embedParentOrigins,
		static: http.FileServer(http.FS(staticFS)),
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式无效"})
		return false
	}
	return true
}

func (a *App) frameAncestors(includeSelf bool) string {
	ancestors := make([]string, 0, len(a.embedParentOrigins)+1)
	if includeSelf {
		ancestors = append(ancestors, "'self'")
	}
	ancestors = append(ancestors, a.embedParentOrigins...)
	if len(ancestors) == 0 {
		return "'none'"
	}
	return strings.Join(ancestors, " ")
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if value, _, ok := strings.Cut(host, ":"); ok {
			host = value
		}
		if a.allowedHost != "" && host != a.allowedHost && host != "localhost" && host != "127.0.0.1" {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		frameAncestors := "'self'"
		isArtifact := strings.HasPrefix(r.URL.Path, "/api/public/results/") && strings.HasSuffix(r.URL.Path, "/artifact")
		if r.URL.Path == "/embed" {
			frameAncestors = a.frameAncestors(false)
		} else if isArtifact {
			frameAncestors = a.frameAncestors(true)
		} else {
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors "+frameAncestors)
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/public/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, a.store.PublicState(a.runner.RunningSnapshot()))
	})
	mux.HandleFunc("GET /api/public/results/{id}", a.publicResult)
	mux.HandleFunc("GET /api/public/results/{id}/artifact", a.publicArtifact)
	mux.HandleFunc("POST /api/admin/login", a.login)
	mux.HandleFunc("POST /api/admin/logout", a.auth.requireSession(a.logout))
	mux.HandleFunc("GET /api/admin/session", a.auth.requireSession(a.session))
	mux.HandleFunc("GET /api/admin/state", a.auth.requireSession(a.adminState))
	mux.HandleFunc("PUT /api/admin/settings", a.auth.requireSession(a.updateSettings))
	mux.HandleFunc("PUT /api/admin/notifications", a.auth.requireSession(a.updateNotifications))
	mux.HandleFunc("DELETE /api/admin/notifications", a.auth.requireSession(a.clearNotifications))
	mux.HandleFunc("POST /api/admin/notifications/test", a.auth.requireSession(a.testNotification))
	mux.HandleFunc("POST /api/admin/targets", a.auth.requireSession(a.createTarget))
	mux.HandleFunc("PUT /api/admin/targets/{id}", a.auth.requireSession(a.updateTarget))
	mux.HandleFunc("DELETE /api/admin/targets/{id}", a.auth.requireSession(a.deleteTarget))
	mux.HandleFunc("POST /api/admin/targets/{id}/run", a.auth.requireSession(a.runTarget))
	mux.HandleFunc("GET /admin", a.serveAdmin)
	mux.HandleFunc("GET /embed", a.serveEmbed)
	mux.HandleFunc("GET /", a.serveIndex)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", a.static))
	return a.securityHeaders(mux)
}

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.serveStaticFile(w, r, "index.html")
}

func (a *App) serveAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	a.serveStaticFile(w, r, "admin.html")
}

func (a *App) serveEmbed(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/embed" {
		http.NotFound(w, r)
		return
	}
	a.serveStaticFile(w, r, "index.html")
}

func (a *App) serveStaticFile(w http.ResponseWriter, r *http.Request, name string) {
	data, err := webFiles.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (a *App) publicResult(w http.ResponseWriter, r *http.Request) {
	result, ok := a.store.PublicResult(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "记录不存在"})
		return
	}
	result = publicResult(result)
	result.ArtifactFile = ""
	writeJSON(w, http.StatusOK, result)
}

func (a *App) publicArtifact(w http.ResponseWriter, r *http.Request) {
	result, ok := a.store.PublicResult(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := a.store.Artifact(result)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; media-src data: blob:; font-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors "+a.frameAncestors(true))
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(data)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.auth.checkOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "请求来源无效"})
		return
	}
	if !a.auth.allowLogin(r) {
		w.Header().Set("Retry-After", "900")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "登录尝试过多，请稍后再试"})
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if !a.auth.validAdminToken(request.Token) {
		time.Sleep(350 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "管理员口令无效"})
		return
	}
	claims, err := a.auth.issueSession(w)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "无法创建登录会话"})
		return
	}
	a.auth.clearAttempts(r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": claims.CSRF, "expires_at": claims.ExpiresAt})
}

func (a *App) logout(w http.ResponseWriter, _ *http.Request) {
	a.auth.clearSession(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) session(w http.ResponseWriter, r *http.Request) {
	info, err := a.auth.sessionInfo(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "需要管理员登录"})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *App) adminState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.store.AdminState(a.runner.RunningSnapshot()))
}

func (a *App) updateSettings(w http.ResponseWriter, r *http.Request) {
	var request struct {
		BaseURL string `json:"base_url"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := a.store.SetBaseURL(request.BaseURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) updateNotifications(w http.ResponseWriter, r *http.Request) {
	var request struct {
		BarkURL   string `json:"bark_url"`
		NotifyAll bool   `json:"notify_all"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.BarkURL) != "" {
		if err := a.store.SetBarkURL(request.BarkURL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	} else if _, configured := a.store.BarkURL(); !configured {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请先填写 Bark 地址"})
		return
	}
	if err := a.store.SetNotifyAll(request.NotifyAll); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "通知设置保存失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) clearNotifications(w http.ResponseWriter, _ *http.Request) {
	if err := a.store.SetBarkURL(""); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "通知设置保存失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) testNotification(w http.ResponseWriter, _ *http.Request) {
	if err := a.runner.TestNotification(); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) createTarget(w http.ResponseWriter, r *http.Request) {
	input := TargetInput{Benchmark: "pelican", Model: "gpt-6-astra", ReasoningEffort: "low", IntervalMinutes: 120, CronExpression: "0 8-20/2 * * 1-5", RetainCount: 6, Enabled: true}
	if !decodeJSON(w, r, &input) {
		return
	}
	target, err := a.store.AddTarget(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	target.EncryptedAPIKey = ""
	writeJSON(w, http.StatusCreated, target)
}

func (a *App) updateTarget(w http.ResponseWriter, r *http.Request) {
	var input TargetInput
	if !decodeJSON(w, r, &input) {
		return
	}
	target, err := a.store.UpdateTarget(r.PathValue("id"), input)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "检测目标不存在"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	target.EncryptedAPIKey = ""
	writeJSON(w, http.StatusOK, target)
}

func (a *App) deleteTarget(w http.ResponseWriter, r *http.Request) {
	if a.runner.RunningSnapshot()[r.PathValue("id")] {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "检测运行中，暂时不能删除"})
		return
	}
	err := a.store.DeleteTarget(r.PathValue("id"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "检测目标不存在"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "删除失败"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) runTarget(w http.ResponseWriter, r *http.Request) {
	if !a.runner.RunNow(r.PathValue("id")) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "该分组正在检测"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func main() {
	config := loadConfig()
	app, err := newApp(config)
	if err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app.runner.StartScheduler(ctx)
	server := &http.Server{
		Addr: config.ListenAddr, Handler: app.routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		slog.Info("monitor listening", "address", config.ListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped unexpectedly", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
