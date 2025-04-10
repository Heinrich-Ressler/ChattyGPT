from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from pydantic import EmailStr
from uuid import uuid4
import smtplib
from email.mime.text import MIMEText
from fastapi.security import OAuth2PasswordRequestForm
from authlib.integrations.starlette_client import OAuth

from chatty_auth_service.database import SessionLocal, engine, Base, get_db
from chatty_auth_service.models import User
from chatty_auth_service.utils.security import hash_password, verify_password
from chatty_auth_service.utils.jwt import create_access_token, create_refresh_token, get_current_user
from chatty_auth_service.settings import settings

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

templates = Jinja2Templates(directory="chatty_auth_service/templates")
app.mount("/static", StaticFiles(directory="chatty_auth_service/static"), name="static")

Base.metadata.create_all(bind=engine)

oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.client_id,
    client_secret=settings.client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

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

@app.get("/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email, "id": current_user.id}

@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Email not confirmed")

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie("refresh_token", refresh_token, httponly=True)
    return response

@app.post("/logout")
def logout():
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie("refresh_token")
    return response

@app.post("/refresh")
def refresh_token(request: Request):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token provided")

    try:
        user = get_current_user(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_access_token = create_access_token(data={"sub": user.email})
    return {"access_token": new_access_token, "token_type": "bearer"}

# ===== Google OAuth2 integration =====

@app.get("/login/google")
async def login_via_google(request: Request):
    redirect_uri = request.url_for("auth_google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)

    if not user_info:
        raise HTTPException(status_code=400, detail="Google auth failed")

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not available in Google response")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password_hash="",  # Not used
            is_active=True,
            confirmation_token=None,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    response = RedirectResponse(url="/")
    response.set_cookie("refresh_token", refresh_token, httponly=True)
    return response

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
