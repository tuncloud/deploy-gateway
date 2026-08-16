package main

import (
	"log"
	"log/slog"
	"net/http"

	"github.com/tuncloud/deploy-gateway/internal/api"
)

func main() {
	log.Printf("deploy-gateway listening on :8080")
	// Full dependency wiring (OIDC verifier, policy, dynamo, kube client) lands in Task 11.
	h := api.NewRouter(api.Deps{Log: slog.Default()})
	if err := http.ListenAndServe(":8080", h); err != nil {
		log.Fatal(err)
	}
}
