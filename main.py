from fastapi import FastAPI
from routes.routes import router
from models.base import Base  # Import shared Base from models.base
from sqlalchemy import create_engine

app = FastAPI(
    title="GPG Service API",
    description="REST API for GPG key management, cryptographic operations, and authentication (JWT & API Key)",
    version="0.0.1",
    contact={
        "name": "Damien Trog",
        "email": "damien.trog@gmail.com"
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Initialize the database engine
engine = create_engine("sqlite:///./user_key_store.db", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=engine)  # Create all tables

app.include_router(router)
