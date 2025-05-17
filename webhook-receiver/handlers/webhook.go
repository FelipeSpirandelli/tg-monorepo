package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type WebhookPayload struct {
	Event string                 `json:"event" binding:"required"`
	Data  map[string]interface{} `json:"data" binding:"required"`
}

func WebhookHandler(c *gin.Context) {
	var payload WebhookPayload

	// Bind JSON to payload; returns 400 on error
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// — Hard part: you’d add your processing here —
	// e.g. enqueue to a job, validate event, etc.

	c.JSON(http.StatusOK, gin.H{
		"status": "received",
		"event":  payload.Event,
	})
}
