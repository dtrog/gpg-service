from fastapi import APIRouter, Depends, HTTPException, status, Header, Body
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import secrets
from models.user_credentials import UserCredentials
from models.base import Base  # Import Base from the shared base module
from schemas.sign_request import SignRequest
from schemas.encrypt_request import EncryptRequest
from schemas.decrypt_request import DecryptRequest
from schemas.verify_request import VerifyRequest
from schemas.key_request import KeyRequest
from services.gpg_service import GPGService
from passlib.context import CryptContext

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import logging

# Setup SessionLocal for DB access
engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

SECRET_KEY = "supersecretkey"  # Replace with a secure key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_api_key_header(x_api_key: str = Header(...), db: Session = Depends(get_db)):
    user = APIKeyManager.get_user_by_api_key(x_api_key, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    stmt = select(UserCredentials).where(UserCredentials.username == username)  # Fixed to use User.username
    user = db.execute(stmt).scalars().first()
    if user is None:
        raise credentials_exception
    return user

class APIKeyManager:
    @staticmethod
    def generate_api_key():
        return secrets.token_urlsafe(32)

    @staticmethod
    def assign_api_key(user, db):
        api_key = APIKeyManager.generate_api_key()
        user.api_key = api_key
        db.commit()
        return api_key

    @staticmethod
    def get_user_by_api_key(api_key: str, db: Session = Depends(get_db)):
        stmt = select(UserCredentials).where(UserCredentials.api_key == api_key)  # Fixed to use User.api_key
        return db.execute(stmt).scalars().first()

@router.post("/register")
def register(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logging.debug("Register endpoint called with username: %s", form.username)
    stmt = select(UserCredentials).where(UserCredentials.username == form.username)  # Fixed to use User.username
    if db.execute(stmt).scalars().first():
        logging.debug("Username already registered: %s", form.username)
        raise HTTPException(status_code=400, detail="Username already registered")

    api_key = APIKeyManager.generate_api_key()
    logging.debug("Generated API key for user: %s", form.username)

    user = UserCredentials(
        username=form.username,
        password_hash=get_password_hash(form.password),
        api_key=api_key
    )
    db.add(user)
    logging.debug("User added to session: %s", form.username)
    db.commit()
    logging.debug("Transaction committed for user: %s", form.username)
    return {"message": "User registered successfully", "api_key": api_key}

@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logging.debug("Login endpoint called with username: %s", form.username)
    stmt = select(UserCredentials).where(UserCredentials.username == form.username)  # Fixed to use User.username
    user = db.execute(stmt).scalars().first()
    if not user or not verify_password(form.password, user.password_hash):
        logging.debug("Login failed for username: %s", form.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    logging.debug("Login successful for username: %s", form.username)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/get_api_key")
def get_api_key(user: UserCredentials = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.api_key:
        return {"api_key": user.api_key}
    api_key = APIKeyManager.assign_api_key(user, db)
    return {"api_key": api_key}

@router.post("/generate_keys")
async def generate_keys_endpoint(req: KeyRequest, db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    # Generate keys for the authenticated user using API key as passphrase
    return GPGService().generate_keys(user.username, user.api_key, db)

@router.get("/get_public_key/{username}")
async def get_public_key_endpoint(username: str, db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    return GPGService().get_public_key(username, db)

@router.post("/sign")
async def sign_endpoint(message: str = Body(..., embed=True), db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    # Sign message for authenticated user using API key
    return GPGService().sign_message(user.username, user.api_key, message, db)

@router.post("/encrypt")
async def encrypt_endpoint(message: str = Body(..., embed=True), db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    # Encrypt message for authenticated user
    return GPGService().encrypt_message(user.username, message, db)

@router.post("/decrypt")
async def decrypt_endpoint(encrypted_message: str = Body(..., embed=True), db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    # Decrypt message for authenticated user using API key
    return GPGService().decrypt_message(user.username, user.api_key, encrypted_message, db)

@router.post("/verify")
async def verify_endpoint(signature: str = Body(..., embed=True), message: str = Body(..., embed=True), db: Session = Depends(get_db), user: UserCredentials = Depends(get_current_user)):
    # Verify signature for authenticated user
    return GPGService().verify_signature(user.username, message, signature, db)

@router.post("/generate_keys_api")
async def generate_keys_api(req: KeyRequest, db: Session = Depends(get_db), api_key: str = Header(...)):
    return GPGService().generate_keys(req.username, req.password, db)

@router.get("/get_public_key_api/{username}")
async def get_public_key_api(username: str, db: Session = Depends(get_db), api_key: str = Header(...)):
    return GPGService().get_public_key(username, db)

@router.post("/sign_api")
async def sign_api(req: SignRequest, db: Session = Depends(get_db), user: UserCredentials = Depends(get_user_by_api_key_header)):
    return GPGService().sign_message(req.username, req.password, req.message, db)

@router.post("/encrypt_api")
async def encrypt_api(req: EncryptRequest, db: Session = Depends(get_db), user: UserCredentials = Depends(get_user_by_api_key_header)):
    return GPGService().encrypt_message(req.recipient, req.message, db)

@router.post("/decrypt_api")
async def decrypt_api(req: DecryptRequest, db: Session = Depends(get_db), user: UserCredentials = Depends(get_user_by_api_key_header)):
    return GPGService().decrypt_message(req.username, req.password, req.encrypted_message, db)

@router.post("/verify_api")
async def verify_api(req: VerifyRequest, user: UserCredentials = Depends(get_user_by_api_key_header)):
    return GPGService().verify_signature(req.signature, req.message)