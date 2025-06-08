package database

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"time"

	"authentication-service/src/config"
	"authentication-service/src/logger"

	_ "github.com/lib/pq" // PostgreSQL driver
)

var DB *sql.DB

func ConnectToDB(cfg *config.Config) (*sql.DB, error) {
	// Construct DSN once
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)

	var err error
	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Failed to open DB connection: %v", err))
		return nil, err
	}

	// Use retry helper to ping DB with retries
	err = pingWithRetry(DB, cfg.Logger, 10, 5*time.Second)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Failed to ping DB after retries: %v", err))
		return nil, err
	}

	cfg.Logger.Info("✅ DATABASE connection success!")

	err = runInitSQLScript(cfg)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ DATABASE ERROR: Failed to run initialization SQL script: %v", err))
		return nil, err
	}

	cfg.Logger.Info("✅ DATABASE connection completed successfully")
	return DB, nil
}

func pingWithRetry(db *sql.DB, logger *logger.Logger, maxAttempts int, delay time.Duration) error {
	var err error
	for i := 1; i <= maxAttempts; i++ {
		err = db.Ping()
		if err == nil {
			return nil
		}
		logger.Info(fmt.Sprintf("⏳ Attempt %d/%d: Waiting for database to be ready... error: %v", i, maxAttempts, err))
		time.Sleep(delay)
	}
	return err
}

func runInitSQLScript(cfg *config.Config) error {
	sqlFileContent, err := ioutil.ReadFile(cfg.InitSQLFilePath)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Error reading SQL file: %v", err))
		return err
	}

	_, err = DB.Exec(string(sqlFileContent))
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Error executing SQL: %v", err))
		return err
	}

	cfg.Logger.Info("✅ Successfully initialized the database with the users table")
	return nil
}
