from sqlalchemy.orm import Session
from fastapi import HTTPException
from uuid import uuid4
from pydantic import EmailStr

from chatty_auth_service.models import User
from chatty_auth_service.schemas import UserCreate
from chatty_auth_service.utils.security import hash_password, verify_password
from chatty_auth_service.utils.jwt import create_access_token


def register_user(db: Session, user_data: UserCreate) -> None:
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = hash_password(user_data.password)
    token = str(uuid4())

    new_user = User(
        email=user_data.email,
        password_hash=hashed_pw,
        confirmation_token=token,
        is_active=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    from chatty_auth_service.utils.mailer import send_confirmation_email
    send_confirmation_email(new_user.email, token)


def confirm_user_email(db: Session, token: str) -> None:
    user = db.query(User).filter(User.confirmation_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.is_active = True
    user.confirmation_token = None
    db.commit()


def authenticate_user(db: Session, email: str, password: str) -> str:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Email not confirmed")

    return create_access_token(data={"sub": user.email})


def get_user_by_email(db: Session, email: EmailStr) -> User | None:
    return db.query(User).filter(User.email == email).first()
