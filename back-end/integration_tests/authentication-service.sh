#!/bin/bash

# Load environment variables from .env file
ENV_FILE="../build-tools/.env"
if [ -f "$ENV_FILE" ]; then
  export $(grep -v '^#' "$ENV_FILE" | xargs)
else
  echo "⚠️ .env file not found at $ENV_FILE"
  exit 1
fi

# Install jq (JSON parsing utility) if not already installed
if ! command -v jq &> /dev/null
then
  echo "jq could not be found, installing..."
  sudo apt-get update
  sudo apt-get install -y jq
fi

test_start() {
    echo -e "********************************************************************"
    echo -e "$AUTHENTICATION_SERVICE_NAME API END POINT INTEGRATION TESTS STARTS..."
    echo -e "********************************************************************"
}

test_end() {
    echo -e "********************************************************************"
    echo -e "$AUTHENTICATION_SERVICE_NAME API END POINT INTEGRATION TESTS END..."
    echo -e "********************************************************************"
}

# Define API URLs
BASE_URL="http://localhost:$AUTHENTICATION_SERVICE_PORT"
HEALTH_CHECK_URL="$BASE_URL/auth/health"
REGISTER_URL="$BASE_URL/auth/register"

health_check() {
  echo "===>TEST END POINT--->HEALTH CHECK"
  echo
  echo "REQUEST URL: $HEALTH_CHECK_URL"

  REQUEST_TYPE="GET"

  echo "REQUEST TYPE: $REQUEST_TYPE"
  echo "COMMAND: curl -X $REQUEST_TYPE \"$HEALTH_CHECK_URL\""

  HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X $REQUEST_TYPE "$HEALTH_CHECK_URL")

  HTTP_BODY=$(echo "$HEALTH_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$HEALTH_RESPONSE" | tail -n1)

  echo "Health Check Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Service is healthy!"
  else
    echo "❌ Health check failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo "✅ Health Check successfully"
  echo
}

register_user_test() {
  echo "===>TEST END POINT--->REGISTER NEW USER"
  echo

  local payload='{
    "username": "testuser",
    "mail_address": "testuser@example.com",
    "password": "TestPassword123!",
    "role": "Sales Representative",
    "phone_number": "+1234567890",
    "language_preference": "en"
  }'

  echo "REQUEST URL: $REGISTER_URL"
  echo "REQUEST TYPE: POST"
  echo "REQUEST PAYLOAD: $payload"

  REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$REGISTER_URL" \
    -H "Content-Type: application/json" \
    -d "$payload")

  HTTP_BODY=$(echo "$REGISTER_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$REGISTER_RESPONSE" | tail -n1)

  echo "Register User Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 201 ]; then
    echo "✅ User registered successfully"
  else
    echo "❌ User registration failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

get_last_user_test() {
  echo "===>TEST END POINT--->GET LAST USER FROM DB"
  echo

  LAST_USER_URL="$BASE_URL/auth/last-user"

  echo "REQUEST URL: $LAST_USER_URL"
  echo "REQUEST TYPE: GET"

  RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$LAST_USER_URL" -H "Accept: application/json")

  HTTP_BODY=$(echo "$RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$RESPONSE" | tail -n1)

  echo "Last User Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ Last user fetched successfully"
  else
    echo "❌ Failed to fetch last user with status code $HTTP_STATUS"
    exit 1
  fi

  echo
}


test_start
health_check
register_user_test
get_last_db_row
test_end
