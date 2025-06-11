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
NEW_PASSWORD="NewPass456!"



# Define API URLs
BASE_URL="http://localhost:$AUTHENTICATION_SERVICE_PORT"
HEALTH_CHECK_URL="$BASE_URL/auth/health"
REGISTER_URL="$BASE_URL/auth/register"
LAST_USER_URL="$BASE_URL/auth/last-user"
DELETE_USER_URL="$BASE_URL/auth/delete-user"
LOGIN_URL="$BASE_URL/auth/login"
LOGOUT_URL="$BASE_URL/auth/logout"
GET_USER_URL="$BASE_URL/auth/get-user-by-mail"
REFRESH_TOKEN_URL="$BASE_URL/auth/refresh-jwt-token"
UPDATE_USER_URL="$BASE_URL/auth/update-user"
CHANGE_PASSWORD_URL="$BASE_URL/auth/change-password"
SEND_AUTH_CODE_URL="$BASE_URL/auth/forgot-password"

TOKEN=""

health_check() {
  echo ""
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
  echo ""
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
  echo ""
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

login_user_test() {
  echo ""
  echo "===>TEST END POINT--->LOGIN USER"
  echo

  local payload=$(cat <<EOF
{
  "mail_address": "$TEST_MAIL_ADDRESS",
  "password": "$TEST_PASSWORD"
}
EOF
)

  echo "REQUEST URL: $LOGIN_URL"
  echo "REQUEST TYPE: POST"
  echo "REQUEST PAYLOAD: $payload"

  LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_URL" \
    -H "Content-Type: application/json" \
    -d "$payload")

  HTTP_BODY=$(echo "$LOGIN_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$LOGIN_RESPONSE" | tail -n1)

  echo "Login Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    TOKEN=$(echo "$HTTP_BODY" | jq -r '.token')
    if [[ "$TOKEN" != "null" && "$TOKEN" != "" ]]; then
      echo "✅ User logged in successfully"
      echo "🪪 JWT Token:"
      echo "----------------------------------------"
      echo "$TOKEN"
      echo "----------------------------------------"
    else
      echo "❌ Login succeeded but token is missing"
      exit 1
    fi
  else
    echo "❌ Login failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

logout_user_test() {
  echo ""
  echo "===> TEST END POINT ---> LOGOUT USER"
  echo

  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "❌ No JWT token found from login, cannot test logout"
    exit 1
  fi

  echo "REQUEST URL: $LOGOUT_URL"
  echo "REQUEST TYPE: POST"
  echo "Authorization: Bearer <token>"

  LOGOUT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LOGOUT_URL" \
    -H "Authorization: Bearer $TOKEN")

  HTTP_BODY=$(echo "$LOGOUT_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$LOGOUT_RESPONSE" | tail -n1)

  echo "Logout Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ User logged out successfully"
  else
    echo "❌ Logout failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

refresh_jwt_token_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> REFRESH JWT TOKEN"
  echo

  # Use the token you got from login test as a bearer token here
  if [ -z "$TOKEN" ]; then
    echo "❌ No JWT token available to test refresh"
    exit 1
  fi

  echo "REQUEST URL: $REFRESH_TOKEN_URL"
  echo "REQUEST TYPE: POST"
  echo "Authorization: Bearer $TOKEN"

  REFRESH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$REFRESH_TOKEN_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json")

  HTTP_BODY=$(echo "$REFRESH_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$REFRESH_RESPONSE" | tail -n1)

  echo "Refresh Token Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    NEW_TOKEN=$(echo "$HTTP_BODY" | jq -r '.token')
    if [[ "$NEW_TOKEN" != "null" && "$NEW_TOKEN" != "" ]]; then
      echo "✅ JWT token refreshed successfully"
      echo "🆕 New JWT Token:"
      echo "----------------------------------------"
      echo "$NEW_TOKEN"
      echo "----------------------------------------"
    else
      echo "❌ Refresh succeeded but new token is missing"
      exit 1
    fi
  else
    echo "❌ Refresh failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

get_user_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> GET USER BY MAIL ADDRESS"
  echo

  local request_url="${GET_USER_URL}?mail_address=${TEST_MAIL_ADDRESS}"

  echo "REQUEST URL: $request_url"
  echo "REQUEST TYPE: GET"

  GET_USER_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$request_url" \
    -H "Content-Type: application/json")

  HTTP_BODY=$(echo "$GET_USER_RESPONSE" | sed '$ d')
  HTTP_STATUS=$(echo "$GET_USER_RESPONSE" | tail -n1)

  echo "Get User Response Body: $HTTP_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    USERNAME=$(echo "$HTTP_BODY" | jq -r '.username')
    if [[ "$USERNAME" != "null" && "$USERNAME" != "" ]]; then
      echo "✅ User fetched successfully: $USERNAME"
    else
      echo "❌ User data missing from response"
      exit 1
    fi
  else
    echo "❌ Get user failed with status code $HTTP_STATUS. Response: $HTTP_BODY"
    exit 1
  fi

  echo
}

update_user_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> UPDATE USER"

  REQUEST_TYPE="PUT"
  AUTH_HEADER="Authorization: Bearer $JWT_TOKEN"

  # Prepare the update payload
  REQUEST_PAYLOAD=$(cat <<EOF
{
  "mail_address": "testuser@example.com",
  "username": "updateduser",
  "role": "Admin",
  "activated": true
}
EOF
)

  echo "REQUEST URL: $UPDATE_USER_URL"
  echo "REQUEST TYPE: $REQUEST_TYPE"
  echo "AUTH HEADER: $AUTH_HEADER"
  echo "REQUEST PAYLOAD: $REQUEST_PAYLOAD"

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $REQUEST_TYPE $UPDATE_USER_URL \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "$REQUEST_PAYLOAD")

  # Extract body and status
  RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  echo "Update User Response Body: $RESPONSE_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ User updated successfully"
  else
    echo "❌ Failed to update user"
    exit 1
  fi
}

change_password_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> CHANGE PASSWORD"

  REQUEST_TYPE="POST"
  AUTH_HEADER="Authorization: Bearer $TOKEN"

  REQUEST_PAYLOAD=$(cat <<EOF
{
  "mail_address": "testuser@example.com",
  "old_password": "$TEST_PASSWORD",
  "new_password": "$NEW_PASSWORD"
}
EOF
)

  echo "REQUEST URL: $CHANGE_PASSWORD_URL"
  echo "REQUEST TYPE: $REQUEST_TYPE"
  echo "AUTH HEADER: $AUTH_HEADER"
  echo "REQUEST PAYLOAD: $REQUEST_PAYLOAD"

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $REQUEST_TYPE $CHANGE_PASSWORD_URL \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "$REQUEST_PAYLOAD")

  RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  echo "Change Password Response Body: $RESPONSE_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ Password changed successfully"
  else
    echo "❌ Failed to change password"
  fi
}

send_forgot_password_code_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> SEND FORGOT PASSWORD RESET CODE"

  REQUEST_TYPE="POST"

  REQUEST_PAYLOAD=$(cat <<EOF
{
  "mail_address": "testuser@example.com"
}
EOF
)

  echo "REQUEST URL: $SEND_AUTH_CODE_URL"
  echo "REQUEST TYPE: $REQUEST_TYPE"
  echo "REQUEST PAYLOAD: $REQUEST_PAYLOAD"

  HTTP_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X $REQUEST_TYPE $SEND_AUTH_CODE_URL \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD")

  RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  echo "Send Reset Code Response Body: $RESPONSE_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ Reset code sent to email successfully"
  else
    echo "❌ Failed to send reset code"
  fi
}



delete_user_test() {
  echo ""
  echo "===> TEST ENDPOINT ---> DELETE USER BY MAIL"

  REQUEST_TYPE="DELETE"
  REQUEST_PAYLOAD=$(cat <<EOF
{
  "mail_address": "testuser@example.com"
}
EOF
)

  echo "REQUEST URL: $DELETE_USER_URL"
  echo "REQUEST TYPE: $REQUEST_TYPE"
  echo "REQUEST PAYLOAD: $REQUEST_PAYLOAD"

  HTTP_RESPONSE=$(curl -s --fail -w "HTTPSTATUS:%{http_code}" -X $REQUEST_TYPE $DELETE_USER_URL \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD")

  CURL_EXIT_CODE=$?

  RESPONSE_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTPSTATUS\:.*//g')
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

  if [ $CURL_EXIT_CODE -ne 0 ]; then
    echo "❌ curl command failed (exit code: $CURL_EXIT_CODE)"
    exit 1
  fi

  echo "Delete User Response Body: $RESPONSE_BODY"
  echo "HTTP Status Code: $HTTP_STATUS"

  if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ User deleted successfully"
  else
    echo "❌ Failed to delete user. Status: $HTTP_STATUS"
    echo "Response: $RESPONSE_BODY"
    exit 1
  fi
}


# Run tests
test_start
health_check           # Make sure your service is up
register_user_test     # Create a new user first
get_user_test
last_user_test         # Verify user exists (optional but useful)
login_user_test        # Log in to get the JWT token
sleep 1
change_password_test   # Test password change while logged in
send_forgot_password_code_test
refresh_jwt_token_test # Test refreshing that token while logged in
update_user_test
logout_user_test       # Log out and invalidate the token
delete_user_test       # Delete the user to clean up
test_end
