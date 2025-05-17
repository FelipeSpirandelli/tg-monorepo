package config

import (
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Port      string // address to listen on
	AuthToken string
}

func LoadConfig() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	token := os.Getenv("AUTH_TOKEN")
	if token == "" {
		return nil, errors.New("AUTH_TOKEN is required")
	}

	return &Config{
		Port:      fmt.Sprintf(":%s", port),
		AuthToken: token,
	}, nil
}
