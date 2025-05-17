package middleware

import (
	"net/http"
	"strings"

	"github.com/felipespirandelli/tg-webhook-receiver/config"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware verifies the Authorization header matches cfg.AuthToken.
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		parts := strings.SplitN(auth, "Bearer ", 2)
		// if header missing or token mismatch → reject
		if len(parts) != 2 || parts[1] != cfg.AuthToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}
