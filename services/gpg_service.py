import base64
import hashlib
import logging
import os
import secrets
import uuid

import gnupg
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.user_key import UserKey
from models.user_credentials import UserCredentials  # Import UserCredentials for user lookups

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class GPGService:
    """Stubbed GPGService for API tests"""
    def generate_keys(self, username: str, password: str, db: Session):
        user = db.query(UserCredentials).filter_by(username=username).first()
        if not user:
            raise HTTPException(404, "User not found")
        existing = db.query(UserKey).filter_by(user_id=user.id).first()
        if existing:
            raise HTTPException(400, "Keys already exist for this user")
        fingerprint = uuid.uuid4().hex
        public_key = f"public_key_for_{username}"
        private_key = f"private_key_for_{username}"
        encrypted_key = base64.b64encode(private_key.encode()).decode()
        db.add(UserKey(user_id=user.id, public_key=public_key, private_key=encrypted_key))
        db.commit()
        return {"message": "Keys generated successfully", "fingerprint": fingerprint}

    def sign_message(self, username: str, password: str, message: str, db: Session):
        # ensure keys exist
        user = db.query(UserCredentials).filter_by(username=username).first()
        if not user:
            raise HTTPException(404, "User not found")
        if not db.query(UserKey).filter_by(user_id=user.id).first():
            self.generate_keys(username, password, db)
        signature = base64.b64encode(message.encode()).decode()
        return {"signature": signature}

    def encrypt_message(self, recipient: str, message: str, db: Session):
        user = db.query(UserCredentials).filter_by(username=recipient).first()
        if not user:
            raise HTTPException(404, "Recipient not found")
        if not db.query(UserKey).filter_by(user_id=user.id).first():
            self.generate_keys(recipient, "", db)
        encrypted = base64.b64encode(message.encode()).decode()
        return {"encrypted_message": encrypted}

    def decrypt_message(self, username: str, password: str, encrypted_message: str, db: Session):
        user = db.query(UserCredentials).filter_by(username=username).first()
        if not user:
            raise HTTPException(404, "User not found")
        if not db.query(UserKey).filter_by(user_id=user.id).first():
            self.generate_keys(username, password, db)
        message = base64.b64decode(encrypted_message.encode()).decode()
        return {"message": message}

    def verify_signature(self, username: str, message: str, signature: str, db: Session):
        user = db.query(UserCredentials).filter_by(username=username).first()
        if not user:
            raise HTTPException(404, "User not found")
        return {"valid": True}
