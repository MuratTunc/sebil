package main

import (
	"broker-service/src/config"
	"broker-service/src/server"
)

const (
	// Define the environment variable prefix as a constant
	SERVICE_PREFIX = "BROKER"
)

func main() {

	// Load configuration from environment with the defined prefix
	cfg := config.NewConfig(SERVICE_PREFIX)

	logger := cfg.Logger // Get the logger from the config
	logger.Info("✅ New Config is made by main.go with  successfully")

	server.StartServer(cfg) // Start the HTTP server with the loaded config
}
