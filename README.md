# sebil
``` bash

                [ .env file ]
                    ↓
             [ docker-compose.yml ]
                    ↓
           ┌----------------------┐
           |     Build Phase      |
           |----------------------|
           | 1. Read Dockerfile   |
           | 2. Build Go binary   |
           | 3. Package image     |
           └----------------------┘
                    ↓
         [ Docker Image per service ]
                    ↓
         [ docker-compose up --build ]
                    ↓
         [ Containers running binaries ]
```

## Authentication service

``` bash
[ Client (Frontend) ]
         |
       NGINX
      /     \
[ Auth Service ]   <-- handles /login, /register, /verify, /refresh
[ Broker Service ] <-- receives commands, pushes to Redis/RabbitMQ
         |
    [ Other Services ]
       (mail, user, order, etc.)
```



✅ Authentication Flow (Best Practice)
``` bash
[ UI / Frontend ]
     ↓
POST /auth-service/login
Body: { mailAddress, password }

     ↓
[ Authentication Service ]
- Looks up user by mailAddress in authentication-db
- Verifies password (bcrypt check)
- If valid:
    - Creates JWT (signed with shared secret or private key)
    - JWT includes: { user_id, role, mail, exp }
    - Returns: { success: true, token: <JWT>, user: { role, mail, ... } }

     ↓
[ UI stores JWT securely ]
- localStorage or secure HttpOnly cookie
- Adds JWT to every future request as:
  Authorization: Bearer <JWT>

```

# DATABASE 

### `users` Table Schema

``` bash
FILES:
/authentication-service/src/sql/init_users_table.sql
/authentication-service/src/database/connection.go
/authentication-service/src/models/user.go
```

| Column               | Data Type       | Constraints / Description                                           |
|----------------------|----------------|----------------------------------------------------------------------|
| id                   | SERIAL          | Primary Key                                                          |
| username             | VARCHAR(100)    | Not Null, Unique                                                     |
| mail_address         | VARCHAR(255)    | Not Null, Unique                                                     |
| password             | TEXT            | Not Null                                                             |
| role                 | VARCHAR(50)     | Not Null, must be one of: `'Admin'`, `'Sales Representative'`, `'Customer'` |
| phone_number         | VARCHAR(20)     | Optional                                                              |
| language_preference  | VARCHAR(10)     | Default `'en'`                                                       |
| resetcode            | VARCHAR(20)     | Optional                                                              |
| reset_verified       | BOOLEAN         | Not Null, Default `false`                                            |
| authentication_code  | VARCHAR(20)     | Optional                                                              |
| activated            | BOOLEAN         | Not Null, Default `false`                                            |
| login_status         | BOOLEAN         | Not Null, Default `false`                                            |
| created_at           | TIMESTAMP       | Not Null, Default `CURRENT_TIMESTAMP`                                |
| updated_at           | TIMESTAMP       | Not Null, Default `CURRENT_TIMESTAMP`                                |


### 🧑‍💼 Example Use Cases

| Role                | Permissions                                                                 |
|---------------------|------------------------------------------------------------------------------|
| `Admin`             | Full access: manage users, system settings, view/edit all data               |
| `Sales Representative` | Access customer info, update leads/orders, generate sales reports            |
| `Customer`          | View own profile/orders, update account settings, limited access to features |


## 🔐 Call with JWT Token?

Some endpoints in the authentication service **require a valid JWT token** to ensure that the caller is authenticated and authorized. Whether you need to send a token depends on the **endpoint's access level** and **user role**.

### ✅ Endpoints that **require** JWT Token

| Endpoint                      | Method | Role Required | Description                               |
|-------------------------------|--------|----------------|------------------------------------------|
| `/auth/logout`                | POST   | Any Logged-in  | Invalidate a session                     |
| `/auth/refresh-jwt-token`     | POST   | Any Logged-in  | Refresh JWT token                        |
| `/auth/change-password`       | POST   | Any Logged-in  | Change password                          |
| `/auth/deactivate-user`       | POST   | Admin only     | Deactivate user account                  |
| `/auth/reactivate-user`       | POST   | Admin only     | Reactivate a user account                |
| `/auth/update-user`           | PUT    | Admin or User  | Update user info                         |
| `/auth/delete-user`           | DELETE | Admin only     | Permanently delete a user                |

**Send the JWT token in the `Authorization` header:**

```http
Authorization: Bearer <your_jwt_token>



# HANDLERS


# Register User Handler Flow

1. **Start timer and get logger**  
   - Initialize timing and logging for the registration request.

2. **Parse and validate request**  
   - Parse the incoming JSON to a registration input struct.  
   - If parsing fails, respond with `400 Bad Request` and log the error.  
   - Stop further execution.

3. **Normalize email**  
   - Trim whitespace and convert the email to lowercase.

4. **Check if user exists**  
   - Query the database to check if the username or email already exists.  
   - On database error, respond with `500 Internal Server Error` and log it.  
   - If user exists, respond with `409 Conflict` and a relevant message.  
   - Stop further execution.

5. **Hash the password**  
   - Use bcrypt to hash the plain password.  
   - On error, respond with `500 Internal Server Error` and log it.  
   - Replace the plain password in the input struct with the hashed password.

6. **Insert new user into database**  
   - Insert the user data including hashed password into the users table.  
   - On error, respond with `500 Internal Server Error` and log it.  
   - Stop further execution.

7. **Respond success**  
   - Send `201 Created` response with success message.

8. **Log completion and duration**  
   - Log the successful registration and how long it took.


# Get Last User Handler Flow

1. **Start timer and get logger**  
   - Initialize timing and logging for the request.

2. **Prepare SQL query**  
   - Query to select the latest user by creation date, retrieving:  
     `id`, `username`, `mail_address`, `role`, `activated`, and `created_at`.

3. **Execute query and scan result**  
   - Execute the query with `QueryRow`.  
   - Scan the result into a `User` model struct.  
   - On error (e.g., no rows or DB issue), log the error and respond with `500 Internal Server Error`.

4. **Send JSON response**  
   - Set response header `Content-Type` to `application/json`.  
   - Write status `200 OK`.  
   - Encode the user struct to JSON and write to response.  
   - Log encoding error if it occurs.

5. **Log completion and duration**  
   - Log success message with elapsed time for fetching the user.

# Login User Handler Flow

1. **Start timer and get logger**  
   - Start tracking the request duration.  
   - Initialize logger from app context.

2. **Parse login request**  
   - Decode the JSON request body into a login input struct.  
   - On error, respond with `400 Bad Request` and log the failure.

3. **Fetch user credentials from DB**  
   - Query the database for user ID and hashed password by email.  
   - If query fails (user not found or DB error), handle error with custom handler, respond accordingly, and log.

4. **Validate password**  
   - Compare the hashed password from DB with the provided password.  
   - If invalid, respond with `401 Unauthorized`.

5. **Generate JWT token**  
   - Create a JWT token string containing the user ID and app’s JWT secret and expiration.  
   - On failure, respond with `500 Internal Server Error` and log.

6. **Send response**  
   - Log success with elapsed time.  
   - Set `Content-Type` header to `application/json`.  
   - Encode and send JSON response containing the JWT token.

# Logout User Handler Flow

1. **Start timer and get logger**  
   - Track request duration.  
   - Initialize logger from app context.

2. **Extract Authorization header**  
   - Read the `Authorization` header from the HTTP request.  
   - If missing, respond with `401 Unauthorized` and log the error.

3. **Parse Bearer token**  
   - Extract the token string from the header (expects format: `Bearer <token>`).  
   - If token string is empty or invalid, respond with `401 Unauthorized` and log.

4. **Parse user ID from JWT**  
   - Validate and parse the JWT token to extract the user ID using the app’s JWT secret.  
   - If token is invalid or expired, respond with `401 Unauthorized` and log.

5. **Update user login status**  
   - Update the user’s `login_status` in the database to `false` (logged out).  
   - If DB update fails, respond with `500 Internal Server Error` and log.

6. **Send successful response**  
   - Log logout success with elapsed time.  
   - Set `Content-Type` to `application/json`.  
   - Return JSON response with message `"Logout successful"`.

# Refresh Token Handler Flow

1. **Start timer and get logger**  
   - Record the start time for logging duration.  
   - Get logger instance from app context.

2. **Extract Authorization header**  
   - Read `Authorization` header from the request.  
   - If missing, respond with `401 Unauthorized` and error message for missing token.

3. **Validate Bearer token format**  
   - Split header value by space, expect exactly two parts: `"Bearer"` and token string.  
   - If format invalid, respond with `401 Unauthorized` and error message for invalid token.

4. **Parse user ID from JWT token**  
   - Use the JWT secret to parse and validate the token.  
   - Extract the user ID string from the token claims.  
   - If token parsing fails, respond with `401 Unauthorized` and log the failure.

5. **Convert user ID to integer**  
   - Convert user ID string to integer.  
   - If conversion fails, respond with `401 Unauthorized` and log the error.

6. **Generate new JWT token**  
   - Generate a new JWT token with a fresh expiry using user ID, JWT secret, and expiration config.  
   - If token generation fails, respond with `500 Internal Server Error` and log the error.

7. **Send response**  
   - Log successful token refresh with elapsed time.  
   - Set response `Content-Type` to `application/json`.  
   - Return JSON containing the new token string.

# Get User By Mail Address Handler Flow

1. **Start timer and get logger**  
   - Record the start time for logging duration.  
   - Get logger instance from app context.

2. **Extract `mail_address` query parameter**  
   - Read `mail_address` from URL query parameters.  
   - If missing, respond with `400 Bad Request` and an error message.

3. **Query user by mail address**  
   - Prepare SQL query to select user fields by `mail_address` with a limit of 1.  
   - Execute the query with the provided mail address.

4. **Scan query result into user struct**  
   - Attempt to scan result into user model fields (ID, username, mail_address, role, activated, created_at).  
   - If no user found or error occurs, respond with `404 Not Found` and log the error.

5. **Send successful response**  
   - Set response `Content-Type` to `application/json`.  
   - Respond with HTTP status `200 OK`.  
   - Encode the user struct as JSON in the response body.  
   - If encoding fails, log the error.

6. **Log successful completion**  
   - Log the successful fetch with elapsed time.

# Update User Handler Flow

1. **Start timer and get logger**  
   - Record the start time for logging.  
   - Get logger instance from app context.

2. **Decode request body into UpdateUserRequest struct**  
   - Use JSON decoder to parse the request body.  
   - If decoding fails, log error and respond with `400 Bad Request` and an error message.

3. **Validate required field `mail_address`**  
   - If `mail_address` is empty, respond with `400 Bad Request` and an error message.

4. **Build the update SQL query**  
   - Call `BuildUpdateUserQuery` with provided `username`, `role`, `activated`, and `mail_address`.  
   - If the query builder returns an error, respond with `400 Bad Request` and the error message.

5. **Execute the update query**  
   - Run the built query with its arguments on the database.  
   - If execution fails, log error and respond with `500 Internal Server Error`.

6. **Check rows affected**  
   - If no rows were updated (i.e., `rowsAffected == 0`), respond with `404 Not Found` and an error message indicating no user found.

7. **Respond with success**  
   - Respond with HTTP status `200 OK`.  
   - Write success message "User updated successfully" in the response body.

8. **Log completion**  
   - Log info message indicating successful user update with elapsed time.


# Delete User Handler Flow

1. **Start timer and get logger**  
   - Record the start time for logging.  
   - Get logger instance from app context.

2. **Decode request body into DeleteRequest struct**  
   - Use JSON decoder to parse the request body.  
   - If decoding fails, log error and respond with `400 Bad Request` and an error message.

3. **Validate required field `mail_address`**  
   - If `mail_address` is empty or missing, respond with `400 Bad Request` and an error message.

4. **Execute delete SQL query**  
   - Run `DELETE FROM users WHERE mail_address = $1` with the provided mail address.  
   - If the query execution fails, log error and respond with `500 Internal Server Error`.

5. **Check number of rows affected**  
   - If fetching rows affected results in an error, log it and respond with `500 Internal Server Error`.  
   - If no rows were deleted (`rowsAffected == 0`), respond with `404 Not Found` indicating user not found.

6. **Respond with success**  
   - Respond with HTTP status `200 OK`.  
   - Write success message "User deleted successfully" in the response body.

7. **Log completion**  
   - Log info message indicating successful user deletion with elapsed time.

# ChangePasswordHandler Flow

1. **Start timer and get logger**  
   - Capture current time for logging duration.  
   - Get logger instance from the app context.

2. **Parse request body into `ChangePasswordRequest` struct**  
   - Decode JSON request body.  
   - If decoding fails, respond with `400 Bad Request` and log the error.

3. **Normalize mail address**  
   - Convert the mail address to lowercase for consistency.

4. **Fetch existing hashed password from database**  
   - Query the database for the password hash associated with the given mail address.  
   - If no user found, respond with `404 Not Found`.  
   - If a database error occurs, respond with `500 Internal Server Error`.  
   - Log any error accordingly.

5. **Verify the old password**  
   - Use bcrypt to compare the stored hashed password with the provided old password.  
   - If verification fails, respond with `401 Unauthorized` and log a warning.

6. **Hash the new password**  
   - Generate bcrypt hash from the new password.  
   - If hashing fails, respond with `500 Internal Server Error` and log the error.

7. **Update the password in the database**  
   - Execute an `UPDATE` query to set the new hashed password and update the `updated_at` timestamp for the user.  
   - If update fails, respond with `500 Internal Server Error` and log the error.

8. **Send success response**  
   - Respond with `200 OK` and a success message "Password changed successfully".

9. **Log success with duration**  
   - Log an info message indicating successful password update with elapsed time.


# Forgot Password Handler Flow

1. **Start timer and get logger**  
   - Initialize timing and logging for request monitoring.

2. **Decode JSON request body**  
   - Parse incoming JSON into `ForgotPasswordRequest`.  
   - If decoding fails, respond with `400 Bad Request` and log the error.  
   - Stop further execution.

3. **Normalize email**  
   - Trim spaces and convert the email to lowercase.

4. **Validate email format**  
   - Check if the email contains `"@"`.  
   - If invalid, respond with `400 Bad Request`.  
   - Stop further execution.

5. **Check user existence in DB**  
   - Query the users table by email to get the user ID.  
   - On database errors (except "no rows"), respond with `500 Internal Server Error` and log the error.  
   - Stop further execution.

6. **Handle non-existing user**  
   - If user not found (`sql.ErrNoRows`), respond with `200 OK` and generic message:  
     > "If the email exists, a reset link/code has been sent."  
   - Log the attempt with a note about the unknown email.  
   - Stop further execution.

7. **User exists - generate reset code**  
   - Generate a 6-digit reset code with `generateResetCode()`.  
   - On failure, respond with `500 Internal Server Error` and log the error.  
   - Stop further execution.

8. **Update reset code in DB**  
   - Update the user's record to store the generated reset code.  
   - On failure, respond with `500 Internal Server Error` and log the error.  
   - Stop further execution.

9. **Send reset email asynchronously**  
   - Launch a goroutine to send the reset email with `SendPasswordResetMail`.  
   - Log success or failure of email sending.

10. **Respond with generic success message**  
    - Return `200 OK` with message:  
      > "If the email exists, a reset link/code has been sent."

11. **Log completion and duration**  
    - Log that the forgot password process finished and the elapsed time.


# Integration tests

```bash
✅ Register user using global variables

✅ Fetch last user and verify fields

✅ Delete user cleanly using the username
```


# API Protection

“We use rate limiting and middleware-based API security controls to protect our endpoints from abuse and overuse.”