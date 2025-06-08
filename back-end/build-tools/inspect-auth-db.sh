#!/bin/bash

# Load .env variables from the current directory
set -o allexport
source .env
set +o allexport

# Target container name from env
DB_CONTAINER_NAME=${AUTHENTICATION_POSTGRES_DB_CONTAINER_NAME:-authentication-db}

echo "📦 Connecting to PostgreSQL container: $DB_CONTAINER_NAME"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^$DB_CONTAINER_NAME$"; then
  echo "❌ Container '$DB_CONTAINER_NAME' not found or not running!"
  exit 1
fi

# Menu
while true; do
  echo -e "\n🔍 Choose an option:"
  echo "1) List all tables"
  echo "2) Show schema of 'users' table"
  echo "3) Query top 5 users"
  echo "4) Custom SQL query"
  echo "5) Exit"
  read -p "Enter your choice [1-5]: " choice

  case $choice in
    1)
      docker exec -it "$DB_CONTAINER_NAME" psql -U "$AUTHENTICATION_POSTGRES_DB_USER" -d "$AUTHENTICATION_POSTGRES_DB_NAME" -c "\dt"
      ;;
    2)
      docker exec -it "$DB_CONTAINER_NAME" psql -U "$AUTHENTICATION_POSTGRES_DB_USER" -d "$AUTHENTICATION_POSTGRES_DB_NAME" -c "\d users"
      ;;
    3)
      docker exec -it "$DB_CONTAINER_NAME" psql -U "$AUTHENTICATION_POSTGRES_DB_USER" -d "$AUTHENTICATION_POSTGRES_DB_NAME" -c "SELECT * FROM users LIMIT 5;"
      ;;
    4)
      read -p "Enter your SQL query: " sql
      docker exec -it "$DB_CONTAINER_NAME" psql -U "$AUTHENTICATION_POSTGRES_DB_USER" -d "$AUTHENTICATION_POSTGRES_DB_NAME" -c "$sql"
      ;;
    5)
      echo "👋 Bye!"
      exit 0
      ;;
    *)
      echo "⚠️ Invalid option. Try again."
      ;;
  esac
done
