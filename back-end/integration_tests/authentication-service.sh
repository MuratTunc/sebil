#!/bin/bash

# Load environment variables from .env file
ENV_FILE="../build-tools/.env"
if [ -f "$ENV_FILE" ]; then
  export $(grep -v '^#' "$ENV_FILE" | xargs)
else
  echo "⚠️ .env file not found at $ENV_FILE"
  exit 1
fi

export PGPASSWORD=$AUTHENTICATION_DB_PASSWORD

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
LAST_USER_URL="$BASE_URL/auth/last-user"   # Added last-user endpoint URL

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

last_user_test() {
  echo "===>TEST END POINT--->GET LAST USER"
  echo

  echo "REQUEST URL: $LAST_USER_URL"
  echo "REQUEST TYPE: GET"

  LAST_USER_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$LAST_USER_URL" \
    -H "Content-Type: application/json")

  HTTP_BODY=$(echo "$LAST_USER_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$LAST_USER_RESPONSE" | tail -n1)

  echo "Last User Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -ne 200 ]; then
    echo "❌ Failed to fetch last user with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  # Expected values from registration payload (reuse or hardcode here)
  EXPECTED_USERNAME="testuser"
  EXPECTED_MAIL_ADDRESS="testuser@example.com"
  EXPECTED_ROLE="Sales Representative"

  # Parse the returned JSON values with jq
  ACTUAL_USERNAME=$(echo "$HTTP_BODY" | jq -r '.username')
  ACTUAL_MAIL_ADDRESS=$(echo "$HTTP_BODY" | jq -r '.mail_address')
  ACTUAL_ROLE=$(echo "$HTTP_BODY" | jq -r '.role')

  # Compare expected and actual values
  if [[ "$ACTUAL_USERNAME" == "$EXPECTED_USERNAME" && \
        "$ACTUAL_MAIL_ADDRESS" == "$EXPECTED_MAIL_ADDRESS" && \
        "$ACTUAL_ROLE" == "$EXPECTED_ROLE" ]]; then
    echo "✅ Last user data matches the registered user!"
  else
    echo "❌ Last user data does NOT match the registered user!"
    echo "Expected username: $EXPECTED_USERNAME, got: $ACTUAL_USERNAME"
    echo "Expected mail_address: $EXPECTED_MAIL_ADDRESS, got: $ACTUAL_MAIL_ADDRESS"
    echo "Expected role: $EXPECTED_ROLE, got: $ACTUAL_ROLE"
  fi

  echo
}


test_start
health_check
register_user_test
last_user_test    # call last-user test here
test_end
