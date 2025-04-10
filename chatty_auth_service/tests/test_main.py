import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import Base, get_db
from main import app
import bcrypt
from models import User

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture
def test_user():
    db = TestingSessionLocal()
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=bcrypt.hashpw("testpassword".encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user

def test_register():
    response = client.post("/register", json={
        "username": "newuser",
        "email": "new@example.com",
        "password": "newpassword"
    })
    assert response.status_code == 200
    assert "registered" in response.json()["message"]

def test_login(test_user):
    response = client.post("/login", json={
        "username": "testuser",
        "password": "testpassword"
    })
    assert response.status_code == 200
    assert response.json()["message"] == "Login successful"
