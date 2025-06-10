package config

import (
	"authentication-service/src/logger"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// Set DBPort explicitly to 5432 inside the container
const FixedDBPort = "5432"

type Config struct {
	DBHost          string
	DBUser          string
	DBPassword      string
	DBName          string
	ServicePort     string
	ServiceName     string
	DBPort          string
	EnvPrefix       string
	InitSQLFilePath string
	JWTSecret       string
	UseDB           bool // Flag to determine if DB config is needed
	DB              *sql.DB
	Logger          *logger.Logger
	JWTExpiration   time.Duration
}

// NewConfig initializes the configuration
func NewConfig(envPrefix string) *Config {

	jwtExpStr := os.Getenv(fmt.Sprintf("%s_JWTExpiration", envPrefix))
	jwtExpInt, err := strconv.Atoi(jwtExpStr)
	if err != nil {
		log.Fatalf("Invalid JWTExpiration value: %v", err)
	}

	cfg := &Config{
		EnvPrefix:       envPrefix,
		DBHost:          os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_HOST", envPrefix)),
		DBUser:          os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_USER", envPrefix)),
		DBPassword:      os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_PASSWORD", envPrefix)),
		DBName:          os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_NAME", envPrefix)),
		ServicePort:     os.Getenv(fmt.Sprintf("%s_SERVICE_PORT", envPrefix)),
		ServiceName:     os.Getenv(fmt.Sprintf("%s_SERVICE_NAME", envPrefix)),
		InitSQLFilePath: os.Getenv(fmt.Sprintf("%s_INIT_SQL_FILE_PATH", envPrefix)),
		JWTSecret:       os.Getenv(fmt.Sprintf("%s_JWTSecret", envPrefix)),
		JWTExpiration:   time.Duration(jwtExpInt) * time.Hour,
		DBPort:          FixedDBPort, // fixed port inside the container
		Logger:          logger.NewLogger(logger.INFO),
	}

	cfg.validateEnvVars()
	cfg.printEnvVariables()

	cfg.Logger.Info("✅ Configuration initialized successfully")

	return cfg
}

func (c *Config) printEnvVariables() {

	c.Logger.Info(fmt.Sprintf("🔧 LOADED SERVICE ENVIRONMENTS - %s", c.EnvPrefix))
	c.Logger.Info("🔧 ServicePort: " + c.ServicePort)
	c.Logger.Info("🔧 ServiceName: " + c.ServiceName)
	c.Logger.Info("🔧 DBHost: " + c.DBHost)
	c.Logger.Info("🔧 DBUser: " + c.DBUser)
	c.Logger.Info("🔧 DBPassword: " + c.DBPassword)
	c.Logger.Info("🔧 DBName: " + c.DBName)
	c.Logger.Info("🔧 DBPort: " + c.DBPort)
	c.Logger.Info("🔧 InitSQLFilePath: " + c.InitSQLFilePath)

}

func (c *Config) validateEnvVars() {
	missing := false

	if c.ServicePort == "" || c.ServiceName == "" {
		c.Logger.Error("❌ Missing required service environment variables")
		missing = true
	}

	if c.UseDB {
		if c.DBHost == "" || c.DBUser == "" || c.DBPassword == "" || c.DBName == "" {
			c.Logger.Error("❌ Missing required database environment variables")
			missing = true
		}
	}

	if c.InitSQLFilePath == "" {
		c.Logger.Error("❌ Missing INIT_SQL_FILE_PATH environment variable")
		missing = true
	}

	if missing {
		c.Logger.Error("❌ Exiting due to missing environment variables.")
		os.Exit(1)
	}

}
