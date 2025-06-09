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