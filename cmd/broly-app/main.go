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
	"log"
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
	cfg := loadConfig()

	transport, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, cfg.AppID, cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("failed to create app transport: %v", err)
	}

	app := &App{
		config:    cfg,
		transport: transport,
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
		log.Printf("broly-app listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	log.Println("broly-app shut down")
}

type Config struct {
	AppID          int64
	PrivateKeyPath string
	WebhookSecret  string
	Port           string
}

func loadConfig() Config {
	appID, err := strconv.ParseInt(mustEnv("APP_ID"), 10, 64)
	if err != nil {
		log.Fatalf("APP_ID must be a number: %v", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return Config{
		AppID:          appID,
		PrivateKeyPath: mustEnv("PRIVATE_KEY_PATH"),
		WebhookSecret:  mustEnv("WEBHOOK_SECRET"),
		Port:           port,
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

type App struct {
	config    Config
	transport *ghinstallation.AppsTransport
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
	log.Printf("event: %s delivery: %s", eventType, r.Header.Get("X-GitHub-Delivery"))

	switch eventType {
	case "pull_request":
		a.handlePullRequest(body)
	case "push":
		a.handlePush(body)
	case "installation":
		log.Println("app installed/updated")
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
	Head   prRef  `json:"head"`
	Base   prRef  `json:"base"`
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
		log.Printf("parse PR event: %v", err)
		return
	}

	if event.Action != "opened" && event.Action != "synchronize" {
		return
	}

	log.Printf("PR #%d on %s (action: %s, sha: %s)",
		event.Number, event.Repository.FullName, event.Action, event.PullRequest.Head.SHA)

	client := a.clientForInstallation(event.Installation.ID)

	go a.scanPR(context.Background(), client, scanRequest{
		owner:   event.Repository.Owner.Login,
		repo:    event.Repository.Name,
		cloneURL: event.Repository.CloneURL,
		prNumber: event.Number,
		headSHA: event.PullRequest.Head.SHA,
		baseBranch: event.PullRequest.Base.Ref,
	})
}

func (a *App) handlePush(body []byte) {
	var event pushEvent
	if err := json.Unmarshal(body, &event); err != nil {
		log.Printf("parse push event: %v", err)
		return
	}

	// Only scan pushes to default branch.
	if event.Ref != "refs/heads/main" && event.Ref != "refs/heads/master" {
		return
	}

	log.Printf("push to %s on %s (sha: %s)", event.Ref, event.Repository.FullName, event.After)

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

func (a *App) scanPR(ctx context.Context, client *github.Client, req scanRequest) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("scanning PR #%d on %s/%s at %s", req.prNumber, req.owner, req.repo, req.headSHA)

	// TODO: clone repo, run broly scan, post results back
	_ = client
}

func (a *App) scanPush(ctx context.Context, client *github.Client, req scanRequest) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("scanning push on %s/%s at %s", req.owner, req.repo, req.headSHA)

	// TODO: clone repo, run broly scan, upload SARIF
	_ = client
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
