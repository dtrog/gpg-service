from services.gpg_service import GPGService
import tempfile
from sqlalchemy.orm import Session
from models.user_key import UserKey
import secrets

# Mock DB session for testing
class DummySession:
    def __init__(self):
        self.data = {}
    def execute(self, stmt):
        username = stmt.right.value if hasattr(stmt, 'right') else stmt.whereclause.right.value
        class Result:
            def __init__(self, data):
                self._data = data
            def scalars(self):
                class ScalarList(list):
                    def first(self):
                        return self[0] if self else None
                return ScalarList([self._data.get(username)] if username in self._data else [])
        return Result(self.data)
    def add(self, obj):
        self.data[obj.username] = obj
    def commit(self):
        pass

def test_generate_and_retrieve_encrypted_private_key():
    with tempfile.TemporaryDirectory() as gnupghome:
        db = DummySession()
        gpg_service = GPGService()
        gpg_service.gnupghome = gnupghome
        gpg_service.gpg = gpg_service.gpg.__class__(gnupghome=gnupghome)
        username = 'testuser@example.com'
        password = 'supersecret'
        # Generate keys and store encrypted private key
        result = gpg_service.generate_keys(username, password, db)
        assert 'fingerprint' in result
        # Retrieve and decrypt private key
        privkey_result = gpg_service.get_private_key(username, password, db)
        assert 'PRIVATE KEY' in privkey_result['private_key']
        # Public key retrieval
        pubkey_result = gpg_service.get_public_key(username, db)
        assert 'PUBLIC KEY' in pubkey_result['public_key'] or 'BEGIN PGP PUBLIC KEY BLOCK' in pubkey_result['public_key']

# Additional tests can be added for sign, encrypt, decrypt, verify, etc., using the same encrypted private key approach.

def test_sign_message():
    with tempfile.TemporaryDirectory() as gnupghome:
        db = DummySession()
        gpg_service = GPGService()
        gpg_service.gnupghome = gnupghome
        gpg_service.gpg = gpg_service.gpg.__class__(gnupghome=gnupghome)
        username = 'testuser@example.com'
        password = 'supersecret'
        gpg_service.generate_keys(username, password, db)
        message = 'Hello, Atlantis!'
        sign_result = gpg_service.sign_message(username, password, message, db)
        assert 'signature' in sign_result and sign_result['signature'], 'Signing failed'

def test_verify_signature():
    with tempfile.TemporaryDirectory() as gnupghome:
        db = DummySession()
        gpg_service = GPGService()
        gpg_service.gnupghome = gnupghome
        gpg_service.gpg = gpg_service.gpg.__class__(gnupghome=gnupghome)
        username = 'testuser@example.com'
        password = 'supersecret'
        gpg_service.generate_keys(username, password, db)
        message = 'Hello, Atlantis!'
        sign_result = gpg_service.sign_message(username, password, message, db)
        signature = sign_result['signature']
        # Import public key before verification to ensure it's present in keyring
        verify_result = gpg_service.verify_signature(username, message, signature, db)
        assert verify_result['valid'], 'Signature verification failed'

def test_encrypt_message():
    with tempfile.TemporaryDirectory() as gnupghome:
        db = DummySession()
        gpg_service = GPGService()
        gpg_service.gnupghome = gnupghome
        gpg_service.gpg = gpg_service.gpg.__class__(gnupghome=gnupghome)
        username = 'testuser@example.com'
        password = 'supersecret'
        gpg_service.generate_keys(username, password, db)
        message = 'Hello, Atlantis!'
        encrypt_result = gpg_service.encrypt_message(username, message, db)
        assert 'encrypted_message' in encrypt_result and encrypt_result['encrypted_message'], 'Encryption failed'

def test_decrypt_message():
    with tempfile.TemporaryDirectory() as gnupghome:
        db = DummySession()
        gpg_service = GPGService()
        gpg_service.gnupghome = gnupghome
        gpg_service.gpg = gpg_service.gpg.__class__(gnupghome=gnupghome)
        username = 'testuser@example.com'
        password = 'supersecret'
        gpg_service.generate_keys(username, password, db)
        message = 'Hello, Atlantis!'
        encrypt_result = gpg_service.encrypt_message(username, message, db)
        encrypted_message = encrypt_result['encrypted_message']
        decrypt_result = gpg_service.decrypt_message(username, password, encrypted_message, db)
        assert 'message' in decrypt_result and decrypt_result['message'] == message, 'Decryption failed'
