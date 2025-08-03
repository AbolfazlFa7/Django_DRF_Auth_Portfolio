## Introduction
This project is an authentication API based on **Django REST Framework** designed for portfolio purposes. The main goal of this project is to provide a secure authentication system with features such as registration, login, logout, and two-factor authentication (OTP) via email or phone number. This project is implemented using **JWT** (JSON Web Token) and advanced features like **Celery**, **throttling**, **pagination**, and a good documentation with **drf-spectacular**.

<img src="README files/img/schema_ui.png" width="100%" height="100%">
<img src="README files/img/schema_redoc.png" width="100%" height="100%">

---

## Features
- **Authentication with JWT**: Support for **access** and **refresh** tokens to manage user sessions.
- **Two-factor authentication (OTP)**: Sending verification codes to email or phone number using **SMTP** and **Kavenegar** services.
- **User management**: Ability to register, view, edit, and delete users with specific access levels (admin or account owner).
- **API documentation**: Complete documentation with **Swagger** and **Redoc** for developers.
- **Automated tests**: Comprehensive tests to ensure the correct functioning of **endpoints** using **APITestCase**.
- **Security**: Strong validation for email, password, and phone number, along with **throttling** to prevent abuse.
- **Cache**: Using **LocMemCache** to optimize OTP verification performance.
- **Environment variable support**: Using **python-dotenv** to manage sensitive settings.

---

## Technologies Used
- **Programming Language**: Python 3
- **Web Framework**: Django 4.2.11
- **API Framework**: Django REST Framework
- **Authentication**: rest_framework_simplejwt
- **For sending email and SMS**: Celery
- **Documentation**: drf-spectacular
- **Storage**: SQLite (for development)
- **Cache**: locmem (for development)
- **External Services**:
  - **Kavenegar**: for sending SMS
  - **SMTP Gmail**: for sending email
- **Testing**: Django Test Framework
- **Environment Variable Management**: python-dotenv

---

### Project Structure
- `core/`: Main project settings (settings.py, urls.py, ...)
- `api/`: Main application including models, views, serializers, and tests
- `utils/`: Helper tools like validation and email/SMS services

---

# Installation and Setup

```
mkdir portfolio
cd portfolio
git clone url
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
```

---

You can access the API documentation at the following addresses:
- http://127.0.0.1:8000/api/schema/ui/
- http://127.0.0.1:8000/api/schema/redoc/

---

## API Examples with curl

Here are just some example requests to interact with the API using **curl**:

### 1. Register a New User
Create a new user by sending a POST request to the `/api/users/` endpoint.

```bash
curl -X POST http://127.0.0.1:8000/api/users/ \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser@example.com", "password": "A12345678a@", "first_name": "Abolfazl", "last_name": "Fallahkar"}'
```

**Expected Response** (if successful):
```json
{
  "url": "http://127.0.0.1:8000/api/users/1/",
  "email": "newuser@example.com",
  "id": 1,
  "first_name": "Abolfazl",
  "last_name": "Fallahkar"
}
```

---

### 2. Login and Obtain JWT Tokens
Log in to get **access** and **refresh** tokens using the `/api/token/` endpoint.

```bash
curl -X POST http://127.0.0.1:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser@example.com", "password": "S12345678s@"}'
  # password must have:
  # at least 8 characters long
  # at least one uppercase and one lowercase letter
  # and one Punctuation mark.
```

**Expected Response** (if successful):
```json
{
  "refresh": "your_refresh_token_here",
  "access": "your_access_token_here",
  "email": "newuser@example.com"
}
```

---

### 3. Send OTP for Verification
Send an OTP to the user's email or phone after logging in. Use the `/api/otp/send/` endpoint. Replace `your_access_token_here` with the **access** token from the previous step.

```bash
curl -X POST http://127.0.0.1:8000/api/otp/send/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_access_token_here" \
  -d '{"email_or_phone": "email"}'
```

**Expected Response** (if successful):
```json
{
  "status": "code has been sent to user"
}
```

---

### 4. Verify OTP
Verify the OTP code sent to the user using the `/api/otp/verify/` endpoint. Replace `your_access_token_here` with the **access** token.

```bash
curl -X POST http://127.0.0.1:8000/api/otp/verify/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_access_token_here" \
  -d '{"code": 123456}'
```

**Expected Response** (if successful):
```json
{
  "status": "User has Verified"
}
```

---

### 5. Logout
Log out the user by blacklisting the **refresh** token using the `/api/logout/` endpoint. Replace `your_access_token_here` and `your_refresh_token_here` with the respective tokens.

```bash
curl -X POST http://127.0.0.1:8000/api/logout/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_access_token_here" \
  -d '{"refresh": "your_refresh_token_here"}'
```

**Expected Response** (if successful):
```json
{
  "status": "You have logged out"
}
```

---

# Author:
## Abolfazl Fallahkar

<br>

# Contact:
### Telegram ID: [AbolfazlFa7](https://t.me/AbolfazlFa7)
### Email: [Abolfazlfallahkar8080@gmail.com](mailto:Abolfazlfallahkar8080@gmail.com)