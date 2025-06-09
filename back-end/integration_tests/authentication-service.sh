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

# Global test user parameters
TEST_USERNAME="testuser"
TEST_MAIL_ADDRESS="testuser@example.com"
TEST_PASSWORD="TestPassword123!"
TEST_ROLE="Sales Representative"
TEST_PHONE_NUMBER="+1234567890"
TEST_LANGUAGE="en"



# Define API URLs
BASE_URL="http://localhost:$AUTHENTICATION_SERVICE_PORT"
HEALTH_CHECK_URL="$BASE_URL/auth/health"
REGISTER_URL="$BASE_URL/auth/register"
LAST_USER_URL="$BASE_URL/auth/last-user"
DELETE_USER_URL="$BASE_URL/auth/delete-user"

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

  local payload=$(cat <<EOF
{
  "username": "$TEST_USERNAME",
  "mail_address": "$TEST_MAIL_ADDRESS",
  "password": "$TEST_PASSWORD",
  "role": "$TEST_ROLE",
  "phone_number": "$TEST_PHONE_NUMBER",
  "language_preference": "$TEST_LANGUAGE"
}
EOF
)

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


  ACTUAL_USERNAME=$(echo "$HTTP_BODY" | jq -r '.username')
  ACTUAL_MAIL_ADDRESS=$(echo "$HTTP_BODY" | jq -r '.mail_address')
  ACTUAL_ROLE=$(echo "$HTTP_BODY" | jq -r '.role')

  if [[ "$ACTUAL_USERNAME" == "$TEST_USERNAME" && \
        "$ACTUAL_MAIL_ADDRESS" == "$TEST_MAIL_ADDRESS" && \
        "$ACTUAL_ROLE" == "$TEST_ROLE" ]]; then
    echo "✅ Last user data matches the registered user!"
  else
    echo "❌ Last user data does NOT match the registered user!"
    echo "Expected username: $TEST_USERNAME, got: $ACTUAL_USERNAME"
    echo "Expected mail_address: $TEST_MAIL_ADDRESS, got: $ACTUAL_MAIL_ADDRESS"
    echo "Expected role: $TEST_ROLE, got: $ACTUAL_ROLE"
    exit 1
  fi

  echo
}

delete_user_test() {
  echo "===>TEST END POINT--->DELETE USER"
  echo

  DELETE_USERNAME="$TEST_USERNAME"
  REQUEST_URL="$DELETE_USER_URL?username=$DELETE_USERNAME"
  echo "REQUEST URL: $REQUEST_URL"
  echo "REQUEST TYPE: DELETE"

  DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$REQUEST_URL")

  HTTP_BODY=$(echo "$DELETE_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$DELETE_RESPONSE" | tail -n1)

  echo "Delete User Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ User '$DELETE_USERNAME' deleted successfully"
  else
    echo "❌ Failed to delete user with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

# Run tests
test_start
health_check
register_user_test
last_user_test
delete_user_test
test_end
