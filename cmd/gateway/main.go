package main

import (
	"log"
	"net/http"

	"github.com/tuncloud/deploy-gateway/internal/api"
)

func main() {
	log.Printf("deploy-gateway listening on :8080")
	if err := http.ListenAndServe(":8080", api.NewRouter()); err != nil {
		log.Fatal(err)
	}
}
