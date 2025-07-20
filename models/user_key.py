from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column
from .base import Base

class UserKey(Base):
    """
    SQLAlchemy model for storing GPG user keys.

    Attributes:
        user_id (int): The ID of the user (foreign key).
        public_key (str): The user's GPG public key.
        private_key (str): The user's GPG private key (password-protected).
    """
    __tablename__ = "user_keys"  # Correctly set the table name
    __table_args__ = {'extend_existing': True}

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user_credentials.id"), nullable=False)
    public_key: Mapped[str] = mapped_column(nullable=False)
    private_key: Mapped[str] = mapped_column(nullable=False)
    user: Mapped["UserCredentials"] = relationship("UserCredentials", back_populates="keys")  # Update relationship to reference UserCredentials
