package database

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"time"

	"authentication-service/src/config"

	_ "github.com/lib/pq" // PostgreSQL driver
)

var DB *sql.DB

func ConnectToDB(cfg *config.Config) (*sql.DB, error) {
	// Construct the PostgreSQL connection string
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)

	var err error

	// Retry logic: Try connecting 10 times with a 5-second delay
	for i := 1; i <= 10; i++ {
		DB, err = sql.Open("postgres", dsn)
		if err == nil {
			// Try pinging the DB to ensure it's reachable
			err = DB.Ping()
			if err == nil {
				cfg.Logger.Info("✅ DATABASE connection success!")
				break
			}
		}
		cfg.Logger.Info(fmt.Sprintf("⏳ Attempt %d: Waiting for database to be ready...\n", i))
		time.Sleep(5 * time.Second)
	}

	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ DATABASE ERROR: Failed to connect to database after retries: %v", err))
		return nil, err
	}

	// Run the SQL script to initialize the database (create users table)
	err = runInitSQLScript(cfg)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ DATABASE ERROR: Failed to run initialization SQL script: %v", err))
		return nil, err
	}

	cfg.Logger.Info("✅ DATABASE connection completed successfully")
	return DB, nil
}

// runInitSQLScript reads the SQL file and executes its content to initialize the database.
func runInitSQLScript(cfg *config.Config) error {
	// Read the SQL file content
	sqlFileContent, err := ioutil.ReadFile("back-end/authentication-service/src/sql/init_users_table.sql")
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Error reading SQL file: %v", err))
		return err
	}

	// Execute the SQL content
	_, err = DB.Exec(string(sqlFileContent))
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("❌ Error executing SQL: %v", err))
		return err
	}

	cfg.Logger.Info("✅ Successfully initialized the database with the users table")
	return nil
}
