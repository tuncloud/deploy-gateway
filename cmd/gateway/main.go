package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/api"
	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/kube"
	"github.com/tuncloud/deploy-gateway/internal/notify"
	"github.com/tuncloud/deploy-gateway/internal/operation"
	"github.com/tuncloud/deploy-gateway/internal/store"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"
	audience   = "https://gateway.tuando.app"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	policyPath := envOr("POLICY_PATH", "/etc/gateway/policy.yaml")
	table := envOr("DYNAMO_TABLE", "deploy-gateway-operations")
	addr := ":" + envOr("PORT", "8080")

	policy, err := authz.LoadPolicy(policyPath)
	if err != nil {
		logger.Error("load policy", "err", err)
		os.Exit(1)
	}
	verifier, err := authn.NewVerifier(ctx, oidcIssuer, audience)
	if err != nil {
		logger.Error("oidc verifier", "err", err)
		os.Exit(1)
	}
	k, err := kube.NewInCluster()
	if err != nil {
		logger.Error("kubernetes client", "err", err)
		os.Exit(1)
	}
	st, err := store.NewDynamo(ctx, table)
	if err != nil {
		logger.Error("dynamo store", "err", err)
		os.Exit(1)
	}

	notifier := notify.New(notify.Config{
		BotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		ChatID:   os.Getenv("TELEGRAM_CHAT_ID"),
		APIBase:  envOr("TELEGRAM_API_BASE", "https://api.telegram.org"),
	}, logger)

	ops := operation.NewManager(k, st, notifier, logger, 10*time.Minute)
	go ops.StartSweeper(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(api.Deps{Verifier: verifier, Policy: policy, Ops: ops, Store: st, Log: logger}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	logger.Info("stopped")
}
