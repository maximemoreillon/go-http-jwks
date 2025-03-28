# Go API with JWKS Middleware

This is a Go API using a JWKS (JSON Web Key Set) middleware for authentication.

## Features

- JWT authentication using JWKS
- Single endpoint returning "Hello, World!"

## Environment Variables

To configure the API, set up a `.env` file with the following variable:

```env
# JWKS URI for token validation
JWKS_URI=<your_jwks_uri>
```

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/maximemoreillon/go-http-jwks.git
   cd go-http-jwks
   ```

2. Install dependencies:

   ```sh
   go mod tidy
   ```

3. Run the application:
   ```sh
   go run .
   ```

## Usage

### Request

```http
GET /
Authorization: Bearer <JWT_TOKEN>
```

### Response

```json
{
  "message": "Hello, World!"
}
```

## Requirements

- Go 1.20+
- A valid JWKS URI for authentication
