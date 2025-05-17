package main

import (
	"log"

	"github.com/felipespirandelli/tg-webhook-receiver/config"
	"github.com/felipespirandelli/tg-webhook-receiver/handlers"
	"github.com/felipespirandelli/tg-webhook-receiver/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	router := gin.Default()
	router.SetTrustedProxies(nil)
	router.POST("/webhook", middleware.AuthMiddleware(cfg), handlers.WebhookHandler)
	router.Run(cfg.Port)
}
