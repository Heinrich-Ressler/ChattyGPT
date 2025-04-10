from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from pydantic import EmailStr
from uuid import uuid4
import smtplib
from email.mime.text import MIMEText

from chatty_auth_service.database import SessionLocal, engine, Base, get_db
from chatty_auth_service.models import User
from chatty_auth_service.utils.security import hash_password, verify_password

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

templates = Jinja2Templates(directory="chatty_auth_service/templates")
app.mount("/static", StaticFiles(directory="chatty_auth_service/static"), name="static")

Base.metadata.create_all(bind=engine)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def register_post(
    request: Request,
    email: EmailStr = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(password)
    confirmation_token = str(uuid4())

    new_user = User(
        email=email,
        password_hash=hashed_password,
        is_active=False,
        confirmation_token=confirmation_token,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    send_confirmation_email(email, confirmation_token)
    return templates.TemplateResponse("check_email.html", {"request": request})


@app.get("/confirm")
def confirm_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.confirmation_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.is_active = True
    user.confirmation_token = None
    db.commit()
    return {"message": "Email confirmed. You can now log in."}


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login_post(
    request: Request,
    email: EmailStr = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Email not confirmed")

    # Здесь будет генерация JWT (временно возвращаем заглушку)
    return {"access_token": "fake-jwt-token", "token_type": "bearer"}


def send_confirmation_email(email: str, token: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "your_email@gmail.com"
    smtp_password = "your_password"

    subject = "Confirm your email"
    body = f"Click the link to confirm your email: http://localhost:8000/confirm?token={token}"
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = smtp_username
    message["To"] = email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, [email], message.as_string())
