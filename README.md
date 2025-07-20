# gpg-service

FastAPI-based REST API for GPG key management and cryptographic operations.

## Features
- Generate GPG public/private key pairs for users
- Password-protected private keys
- Retrieve public keys
- Sign, encrypt, decrypt, and verify messages
- Keys are stored securely in a SQLite database

## Project Structure
- `main.py`: FastAPI app exposing the REST API
- `models/`: SQLAlchemy models and database setup
- `schemas/`: Pydantic request/response schemas
- `services/`: GPG cryptographic service class
- `tests/`: Pytest unit tests

## Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd gpg-service
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the API server:
   ```bash
   uvicorn main:app --reload
   ```

## Docker Support

Build the Docker image:
```bash
docker build -t gpg-service .
```

Run the container:
```bash
docker run -d -p 8000:8000 --name gpg-service gpg-service
```

## Usage

### Generate Keys
```bash
curl -X POST "http://127.0.0.1:8000/generate_keys" -H "Content-Type: application/json" -d '{"username": "user1", "password": "password123"}'
```

### Get Public Key
```bash
curl -X GET "http://127.0.0.1:8000/get_public_key/user1"
```

### Encrypt Message
```bash
curl -X POST "http://127.0.0.1:8000/encrypt" -H "Content-Type: application/json" -d '{"recipient": "user1", "message": "Hello, World!"}'
```

### Decrypt Message
```bash
curl -X POST "http://127.0.0.1:8000/decrypt" -H "Content-Type: application/json" -d '{"username": "user1", "password": "password123", "encrypted_message": "<encrypted_message>"}'
```

### Sign Message
```bash
curl -X POST "http://127.0.0.1:8000/sign" -H "Content-Type: application/json" -d '{"username": "user1", "password": "password123", "message": "Hello, World!"}'
```

### Verify Signature
```bash
curl -X POST "http://127.0.0.1:8000/verify" -H "Content-Type: application/json" -d '{"signature": "<signature>", "message": "Hello, World!"}'
```

### OpenAI GPT Integration

You can call these endpoints from OpenAI GPT models using the OpenAI function calling feature or any HTTP client. The API is fully documented via OpenAPI (Swagger) at `/docs` and `/openapi.json`.

#### CORS Support
If you want to call this API from a browser or external service, make sure CORS is enabled in `main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### Example OpenAI Function Schema
You can use the OpenAPI spec at `/openapi.json` to define OpenAI function calls, or use the following example for a function:

```json
{
  "name": "generate_keys",
  "description": "Generate a GPG key pair for a user.",
  "parameters": {
    "type": "object",
    "properties": {
      "username": {"type": "string"},
      "password": {"type": "string"}
    },
    "required": ["username", "password"]
  }
}
```

Repeat for other endpoints as needed.

## Testing

1. Install test dependencies:
   ```bash
   pip install pytest
   ```
2. Run tests:
   ```bash
   pytest
   ```
