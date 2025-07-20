import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool  # Added StaticPool import for shared in-memory DB
import uuid  # Import uuid to generate unique usernames
import logging

from main import app
from routes import get_db
from models.base import Base  # Import Base from the shared base module
from models.user_credentials import UserCredentials  # Import from correct file
from models.user_key import UserKey


# Global test database setup
test_engine = None
TestSessionLocal = None

def get_test_db_setup():
    """Get or create test database setup."""
    global test_engine, TestSessionLocal
    if test_engine is None:
        test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool  # Use StaticPool to share memory DB across connections
        )
        TestSessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
        # Import all models before creating tables to ensure they're registered
        from models.user_credentials import UserCredentials  # Correct import path
        from models.user_key import UserKey
        Base.metadata.create_all(bind=test_engine)
    return test_engine, TestSessionLocal

def override_get_db():
    """Override the get_db dependency to use the persistent test database."""
    _, TestSessionLocal = get_test_db_setup()
    with TestSessionLocal() as db:
        yield db

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture
def test_client():
    """Provide a test client for API testing."""
    return client

def test_register_user(test_client):
    """Test user registration endpoint."""
    response = test_client.post(
        "/register",
        data={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    assert "api_key" in response.json()


def test_login_user(test_client):
    """Test user login endpoint."""
    unique_username = f"testuser_{uuid.uuid4()}"  # Generate a unique username
    register_response = test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    logging.debug("Register response: %s", register_response.json())
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    logging.debug("Login response: %s", login_response.json())
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

def test_get_api_key(test_client):
    """Test retrieving API key for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"  # Generate a unique username
    register_response = test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    api_key = register_response.json()["api_key"]

    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()
    token = login_response.json()["access_token"]

    response = test_client.post(
        "/get_api_key",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["api_key"] == api_key

def test_generate_keys(test_client):
    """Test generating GPG keys for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"  # Generate a unique username
    test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()
    token = login_response.json()["access_token"]

    response = test_client.post(
        "/generate_keys",
        json={"username": "testuser", "password": "testpass"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "fingerprint" in response.json()

def test_sign_message(test_client):
    """Test signing a message for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"
    test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = test_client.post(
        "/sign",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Hello, Atlantis!"}
    )
    assert response.status_code == 200
    assert "signature" in response.json()

def test_verify_signature(test_client):
    """Test verifying a signed message for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"
    test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    sign_response = test_client.post(
        "/sign",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Hello, Atlantis!"}
    )
    signature = sign_response.json()["signature"]

    response = test_client.post(
        "/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Hello, Atlantis!", "signature": signature}
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True

def test_encrypt_message(test_client):
    """Test encrypting a message for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"
    test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = test_client.post(
        "/encrypt",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Hello, Atlantis!"}
    )
    assert response.status_code == 200
    assert "encrypted_message" in response.json()

def test_decrypt_message(test_client):
    """Test decrypting a message for a user."""
    unique_username = f"testuser_{uuid.uuid4()}"
    test_client.post(
        "/register",
        data={"username": unique_username, "password": "testpass"}
    )
    login_response = test_client.post(
        "/login",
        data={"username": unique_username, "password": "testpass"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    encrypt_response = test_client.post(
        "/encrypt",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Hello, Atlantis!"}
    )
    encrypted_message = encrypt_response.json()["encrypted_message"]

    response = test_client.post(
        "/decrypt",
        headers={"Authorization": f"Bearer {token}"},
        json={"encrypted_message": encrypted_message}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Hello, Atlantis!"
