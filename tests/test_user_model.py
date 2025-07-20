import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from models.user_credentials import UserCredentials, Base
from models.user_key import UserKey

def setup_database():
    """Set up an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)  # Ensure all models are included
    return engine, SessionLocal

@pytest.fixture
def db_session():
    """Provide a SQLAlchemy session for tests."""
    engine, SessionLocal = setup_database()
    with SessionLocal() as session:
        yield session
    engine.dispose()

def test_create_user(db_session):
    """Test creating a new user."""
    user = UserCredentials(username="testuser", password_hash="hashedpassword", api_key="testapikey")
    db_session.add(user)
    db_session.commit()

    stmt = select(UserCredentials).where(UserCredentials.username == "testuser")
    retrieved_user = db_session.execute(stmt).scalars().first()
    assert retrieved_user is not None
    assert retrieved_user.username == "testuser"
    assert retrieved_user.password_hash == "hashedpassword"
    assert retrieved_user.api_key == "testapikey"

def test_duplicate_user(db_session):
    """Test that duplicate usernames are not allowed."""
    user1 = UserCredentials(username="testuser", password_hash="hashedpassword1", api_key="apikey1")
    user2 = UserCredentials(username="testuser", password_hash="hashedpassword2", api_key="apikey2")

    db_session.add(user1)
    db_session.commit()

    with pytest.raises(Exception):
        db_session.add(user2)
        db_session.commit()

def test_user_persistence():
    """Test if User model persists correctly in the database."""
    engine, SessionLocal = setup_database()
    with SessionLocal() as session:
        user = UserCredentials(username="testuser", password_hash="hashedpassword", api_key="testapikey")
        session.add(user)
        session.commit()

        persisted_user = session.query(UserCredentials).filter_by(username="testuser").first()
        assert persisted_user is not None
        assert persisted_user.username == "testuser"
        assert persisted_user.password_hash == "hashedpassword"
        assert persisted_user.api_key == "testapikey"

def test_user_key_persistence():
    """Test if UserKey model persists correctly in the database."""
    engine, SessionLocal = setup_database()
    with SessionLocal() as session:
        user_key = UserKey(user_id=1, public_key="testpublickey", private_key="testprivatekey")
        session.add(user_key)
        session.commit()

        persisted_user_key = session.query(UserKey).filter_by(user_id=1).first()
        assert persisted_user_key is not None
        assert persisted_user_key.public_key == "testpublickey"
        assert persisted_user_key.private_key == "testprivatekey"
