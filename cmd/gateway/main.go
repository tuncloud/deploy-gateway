package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tuncloud/deploy-gateway/internal/api"
	"github.com/tuncloud/deploy-gateway/internal/authn"
	"github.com/tuncloud/deploy-gateway/internal/authz"
	"github.com/tuncloud/deploy-gateway/internal/keycloak"
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

// requireKeycloakConfig fails the process at boot when a Keycloak-backed
// backend is selected without complete configuration. This is a configuration
// error, not a network dependency, so it is the one Keycloak-related thing
// that should exit rather than degrade — in particular the secret: read but
// unvalidated, a misspelled Secret key started cleanly and surfaced much later
// as "keycloak: token endpoint returned 401", which sends the operator to
// debug service-account roles instead of a missing value.
//
// The message names the variables and never their values: the client secret
// must not reach a log line or an error string.
func requireKeycloakConfig(backend string, cfg keycloak.Config) error {
	var missing []string
	for _, v := range []struct {
		name, value string
	}{
		{"KEYCLOAK_BASE_URL", cfg.BaseURL},
		{"KEYCLOAK_REALM", cfg.Realm},
		{"KEYCLOAK_CLIENT_ID", cfg.ClientID},
		{"KEYCLOAK_CLIENT_SECRET", cfg.ClientSecret},
	} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("AUTHZ_BACKEND=%s requires %s", backend,
			strings.Join(missing, ", "))
	}
	return nil
}

// buildAuthorizer selects the authorization backend. Keycloak is resolved
// lazily and never fails the process at boot: a Keycloak hiccup during a
// gateway rollout must not produce a crashlooping gateway at the exact moment
// deploys are needed. /readyz gates traffic instead.
func buildAuthorizer(backend, policyPath string, logger *slog.Logger) (authz.Authorizer, error) {
	kcConfig := func() keycloak.Config {
		return keycloak.Config{
			BaseURL:      os.Getenv("KEYCLOAK_BASE_URL"),
			Realm:        os.Getenv("KEYCLOAK_REALM"),
			ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
			ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		}
	}

	switch backend {
	case "keycloak":
		cfg := kcConfig()
		if err := requireKeycloakConfig(backend, cfg); err != nil {
			return nil, err
		}
		logger.Info("authorization backend", "backend", "keycloak",
			"realm", cfg.Realm, "client_id", cfg.ClientID)
		return keycloak.NewAuthorizer(cfg, logger, keycloak.RealClock{}), nil

	case "shadow":
		file, err := authz.NewFileAuthorizer(policyPath)
		if err != nil {
			return nil, err
		}
		cfg := kcConfig()
		if err := requireKeycloakConfig(backend, cfg); err != nil {
			return nil, err
		}
		logger.Info("authorization backend", "backend", "shadow",
			"authoritative", "file", "shadowed", "keycloak")
		return authz.NewShadow(file,
			keycloak.NewAuthorizer(cfg, logger, keycloak.RealClock{}), logger), nil

	case "file", "":
		logger.Info("authorization backend", "backend", "file", "path", policyPath)
		return authz.NewFileAuthorizer(policyPath)

	default:
		return nil, fmt.Errorf("unknown AUTHZ_BACKEND %q (want file, keycloak or shadow)", backend)
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	policyPath := envOr("POLICY_PATH", "/etc/gateway/policy.yaml")
	table := envOr("DYNAMO_TABLE", "deploy-gateway-operations")
	addr := ":" + envOr("PORT", "8080")

	authorizer, err := buildAuthorizer(os.Getenv("AUTHZ_BACKEND"), policyPath, logger)
	if err != nil {
		logger.Error("authorization backend", "err", err)
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
		APIBase:  os.Getenv("TELEGRAM_API_BASE"),
	}, logger)

	ops := operation.NewManager(k, st, notifier, logger, 10*time.Minute)
	go ops.StartSweeper(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(api.Deps{Verifier: verifier, Authz: authorizer, Ops: ops, Store: st, Log: logger}),
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
