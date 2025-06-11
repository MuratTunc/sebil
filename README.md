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

### 🧑‍💼 Example Use Cases

| Role                | Permissions                                                                 |
|---------------------|------------------------------------------------------------------------------|
| `Admin`             | Full access: manage users, system settings, view/edit all data               |
| `Sales Representative` | Access customer info, update leads/orders, generate sales reports            |
| `Customer`          | View own profile/orders, update account settings, limited access to features |


# Integration tests

```bash
✅ Register user using global variables

✅ Fetch last user and verify fields

✅ Delete user cleanly using the username
```


# handlers.go
```bash
✅ SignUp (RegisterUserHandler):
Purpose: Register a new user.

Steps:

Parse and validate input.

Check if user already exists.

Hash the password.

Save the user in the database.

✅ Done.
```

```bash
✅ SignIn (LoginHandler):
Purpose: Authenticate an existing user and issue a JWT.

Steps:

Parse email (or username) and password from request.

Look up user in the DB.

Compare hashed password using bcrypt.CompareHashAndPassword.

If valid:

Generate a JWT (access token).

Respond with the token (and optionally user info).

If not valid:

Respond with 401 Unauthorized.
```


```bash
✅ ForgotPasswordHandler:

🔐 Purpose:
When a user forgets their password, they can enter their email address. If it exists in the system, the backend should:

Generate a secure reset code (or link).

Store it temporarily (e.g., in DB or Redis).

Email the reset code to the user.

```
