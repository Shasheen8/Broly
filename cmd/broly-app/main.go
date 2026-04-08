// broly-app is a GitHub App webhook server that scans PRs and pushes with Broly.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg := loadConfig()

	transport, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, cfg.AppID, cfg.PrivateKeyPath)
	if err != nil {
		slog.Error("failed to create app transport", "err", err)
		os.Exit(1)
	}

	app := &App{
		config:    cfg,
		transport: transport,
		scanSem:   make(chan struct{}, cfg.MaxConcurrent),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", app.handleWebhook)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("broly-app listening", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	slog.Info("broly-app shut down")
}

type Config struct {
	AppID          int64
	PrivateKeyPath string
	WebhookSecret  string
	Port           string
	MaxConcurrent  int
}

func loadConfig() Config {
	appID, err := strconv.ParseInt(mustEnv("APP_ID"), 10, 64)
	if err != nil {
		slog.Error("APP_ID must be a number", "err", err)
		os.Exit(1)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	maxConcurrent := 4
	if v := os.Getenv("MAX_CONCURRENT_SCANS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxConcurrent = n
		}
	}
	return Config{
		AppID:          appID,
		PrivateKeyPath: mustEnv("PRIVATE_KEY_PATH"),
		WebhookSecret:  mustEnv("WEBHOOK_SECRET"),
		Port:           port,
		MaxConcurrent:  maxConcurrent,
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

type App struct {
	config    Config
	transport *ghinstallation.AppsTransport
	scanSem   chan struct{} // limits concurrent scans
}

func (a *App) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if !verifySignature(body, r.Header.Get("X-Hub-Signature-256"), a.config.WebhookSecret) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	slog.Info("webhook received", "event", eventType, "delivery", r.Header.Get("X-GitHub-Delivery"))

	switch eventType {
	case "pull_request":
		a.handlePullRequest(body)
	case "push":
		a.handlePush(body)
	case "installation":
		slog.Info("app installed/updated")
	}

	w.WriteHeader(http.StatusOK)
}

type pullRequestEvent struct {
	Action       string `json:"action"`
	Number       int    `json:"number"`
	PullRequest  prInfo `json:"pull_request"`
	Repository   repo   `json:"repository"`
	Installation inst   `json:"installation"`
}

type prInfo struct {
	Head prRef `json:"head"`
	Base prRef `json:"base"`
}

type prRef struct {
	SHA string `json:"sha"`
	Ref string `json:"ref"`
}

type pushEvent struct {
	Ref          string `json:"ref"`
	After        string `json:"after"`
	Repository   repo   `json:"repository"`
	Installation inst   `json:"installation"`
}

type repo struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	Name string `json:"name"`
}

type inst struct {
	ID int64 `json:"id"`
}

func (a *App) handlePullRequest(body []byte) {
	var event pullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		slog.Error("parse PR event", "err", err)
		return
	}

	if event.Action != "opened" && event.Action != "synchronize" {
		return
	}

	slog.Info("pull_request received",
		"repo", event.Repository.FullName,
		"pr", event.Number,
		"action", event.Action,
		"sha", event.PullRequest.Head.SHA,
	)

	client := a.clientForInstallation(event.Installation.ID)

	go a.scanPR(context.Background(), client, scanRequest{
		owner:      event.Repository.Owner.Login,
		repo:       event.Repository.Name,
		cloneURL:   event.Repository.CloneURL,
		prNumber:   event.Number,
		headSHA:    event.PullRequest.Head.SHA,
		baseBranch: event.PullRequest.Base.Ref,
	})
}

func (a *App) handlePush(body []byte) {
	var event pushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		slog.Error("parse push event", "err", err)
		return
	}

	// Only scan pushes to default branch.
	if event.Ref != "refs/heads/main" && event.Ref != "refs/heads/master" {
		return
	}

	slog.Info("push received", "repo", event.Repository.FullName, "ref", event.Ref, "sha", event.After)

	client := a.clientForInstallation(event.Installation.ID)

	go a.scanPush(context.Background(), client, scanRequest{
		owner:    event.Repository.Owner.Login,
		repo:     event.Repository.Name,
		cloneURL: event.Repository.CloneURL,
		headSHA:  event.After,
	})
}

type scanRequest struct {
	owner      string
	repo       string
	cloneURL   string
	prNumber   int
	headSHA    string
	baseBranch string
}

func (a *App) clientForInstallation(installationID int64) *github.Client {
	itr := ghinstallation.NewFromAppsTransport(a.transport, installationID)
	return github.NewClient(&http.Client{Transport: itr})
}

func verifySignature(payload []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}
