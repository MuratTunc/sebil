package config

import (
	"broker-service/src/logger"
	"fmt"
	"os"
	"strings"

	"gorm.io/gorm"
)

// Set DBPort explicitly to 5432 inside the container
const FixedDBPort = "5432"

type Config struct {
	DBHost      string
	DBUser      string
	DBPassword  string
	DBName      string
	ServicePort string
	ServiceName string
	DBPort      string
	EnvPrefix   string
	UseDB       bool // Flag to determine if DB config is needed
	DB          *gorm.DB
	Logger      *logger.Logger
}

// NewConfig initializes the configuration
func NewConfig(envPrefix string) *Config {
	useDB := strings.ToLower(os.Getenv(fmt.Sprintf("%s_USE_DB", envPrefix))) == "true"

	cfg := &Config{
		EnvPrefix:   envPrefix,
		ServicePort: os.Getenv(fmt.Sprintf("%s_SERVICE_PORT", envPrefix)),
		ServiceName: os.Getenv(fmt.Sprintf("%s_SERVICE_NAME", envPrefix)),
		UseDB:       useDB,
		DBPort:      FixedDBPort, // fixed port inside the container
		Logger:      logger.NewLogger(logger.INFO),
	}

	if useDB {
		cfg.DBHost = os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_HOST", envPrefix))
		cfg.DBUser = os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_USER", envPrefix))
		cfg.DBPassword = os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_PASSWORD", envPrefix))
		cfg.DBName = os.Getenv(fmt.Sprintf("%s_POSTGRES_DB_NAME", envPrefix))
	}

	cfg.validateEnvVars()
	cfg.printEnvVariables()

	cfg.Logger.Info("✅ Configuration initialized successfully")

	return cfg
}

func (c *Config) printEnvVariables() {
	c.Logger.Info(fmt.Sprintf("🔧 LOADED SERVICE ENVIRONMENTS - %s", c.EnvPrefix))
	c.Logger.Info("🔧ServicePort: " + c.ServicePort)
	c.Logger.Info("🔧ServiceName: " + c.ServiceName)
	c.Logger.Info(fmt.Sprintf("🔧UseDB: %v", c.UseDB))

	if c.UseDB {
		c.Logger.Info("🔧DBHost: " + c.DBHost)
		c.Logger.Info("🔧DBUser: " + c.DBUser)
		c.Logger.Info("🔧DBPassword: " + c.DBPassword)
		c.Logger.Info("🔧DBName: " + c.DBName)
		c.Logger.Info("🔧DBPort: " + c.DBPort)
	}
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

	if missing {
		c.Logger.Error("❌ Exiting due to missing environment variables.")
		os.Exit(1)
	}
}
