from sqlalchemy.orm import relationship, Mapped, mapped_column
from .base import Base

class UserCredentials(Base):
    """
    SQLAlchemy model for storing registered user credentials.

    Attributes:
        id (int): The unique identifier for the user.
        username (str): The unique username for the user.
        password_hash (str): The hashed password for authentication.
    """
    __tablename__ = "user_credentials"  # Fix table name to match foreign key reference
    __table_args__ = {'extend_existing': True}

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)  # Removed index=True since primary key is already indexed
    password_hash: Mapped[str] = mapped_column(nullable=False)
    api_key: Mapped[str] = mapped_column(nullable=False)
    keys: Mapped[list["UserKey"]] = relationship("UserKey", back_populates="user", cascade="all, delete-orphan")  # Correct type argument and ensure reference is resolved
