import os
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import JWTError, jwt
import sqlite3  # Stand-in for backend DB; actual DB connection config done via .env

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

DB_URL = os.getenv("DB_URL", "notes.db")  # For demonstration, using sqlite file

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(
    title="Notes API",
    version="1.0.0",
    description="CRUD and Authentication APIs for Notes Backend",
    openapi_tags=[
        {"name": "auth", "description": "User authentication (signup, login)"},
        {"name": "notes", "description": "CRUD and search endpoints for notes"}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === DATABASE UTILITIES ===
def get_db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Users table (VERY simplistic; in prod, passwords should be hashed+salted!)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    """)
    # Notes table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()

@app.on_event("startup")
def on_startup():
    """Initialize DB on startup."""
    init_db()

# === SCHEMAS ===
class UserSignup(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=6, description="User's password")

class UserLogin(UserSignup):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: int
    email: str

class NoteIn(BaseModel):
    title: str = Field(..., description="Note title")
    content: Optional[str] = Field("", description="Note content")

class NoteOut(NoteIn):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime

# === UTILS ===
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """PUBLIC_INTERFACE. Create JWT for user."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, db_password):
    """In real app, hash & compare!"""
    return plain_password == db_password

def get_user_by_email(email: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """PUBLIC_INTERFACE. Get current user from JWT in Authorization header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("user_id"))
        email: str = payload.get("email")
        if user_id is None or email is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id, email=email)
    except JWTError:
        raise credentials_exception
    db_user = get_user(user_id=token_data.user_id)
    if not db_user:
        raise credentials_exception
    return {"id": db_user["id"], "email": db_user["email"]}

# === AUTH ROUTES ===

# PUBLIC_INTERFACE
@app.post("/auth/signup", tags=["auth"], response_model=Token, summary="Register a new user", description="Sign up for a new account and receive a token.")
def signup(user: UserSignup):
    """Register a new user."""
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (user.email, user.password))
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    token = create_access_token({"user_id": user_id, "email": user.email})
    return {"access_token": token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.post("/auth/login", tags=["auth"], response_model=Token, summary="Login and receive auth token", description="User login endpoint. Returns JWT token on success.")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login an existing user and return auth token."""
    user_row = get_user_by_email(form_data.username)
    if not user_row or not verify_password(form_data.password, user_row["password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"user_id": user_row["id"], "email": user_row["email"]})
    return {"access_token": token, "token_type": "bearer"}

# === NOTES ROUTES ===

# PUBLIC_INTERFACE
@app.post("/notes/", tags=["notes"], response_model=NoteOut, status_code=201, summary="Create note",
          description="Create a note for the authenticated user.")
def create_note(note_in: NoteIn, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notes (title, content, user_id, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (note_in.title, note_in.content, current_user["id"])
    )
    note_id = cur.lastrowid
    conn.commit()
    cur.execute("SELECT * FROM notes WHERE id=?", (note_id,))
    row = cur.fetchone()
    conn.close()
    return NoteOut(**dict(row))

# PUBLIC_INTERFACE
@app.get("/notes/", tags=["notes"], response_model=List[NoteOut], summary="Get all notes",
         description="Return all notes for the current user, optionally filtered by search.")
def list_notes(search: Optional[str] = Query(None, description="Filter notes by search term"),
               current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    if search:
        query = """SELECT * FROM notes WHERE user_id=? AND (title LIKE ? OR content LIKE ?) ORDER BY created_at DESC"""
        param = (current_user["id"], f"%{search}%", f"%{search}%")
        cur.execute(query, param)
    else:
        cur.execute("SELECT * FROM notes WHERE user_id=? ORDER BY created_at DESC", (current_user["id"],))
    rows = [NoteOut(**dict(row)) for row in cur.fetchall()]
    conn.close()
    return rows

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", tags=["notes"], response_model=NoteOut, summary="Get note by ID",
         description="Return a specific note belonging to the current user.")
def get_note(note_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, current_user["id"]))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteOut(**dict(row))

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", tags=["notes"], response_model=NoteOut, summary="Update note",
         description="Update a note belonging to the current user.")
def update_note(note_id: int, note_in: NoteIn, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, current_user["id"]))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Note not found")
    cur.execute(
        "UPDATE notes SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
        (note_in.title, note_in.content, note_id, current_user["id"]))
    conn.commit()
    cur.execute("SELECT * FROM notes WHERE id=?", (note_id,))
    updated_row = cur.fetchone()
    conn.close()
    return NoteOut(**dict(updated_row))

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", tags=["notes"], status_code=204, summary="Delete note",
            description="Delete a note for the current user.")
def delete_note(note_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, current_user["id"]))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Note not found")
    cur.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, current_user["id"]))
    conn.commit()
    conn.close()
    return

# PUBLIC_INTERFACE
@app.get("/", tags=["health"], summary="Health Check")
def health_check():
    """Simple API health check endpoint."""
    return {"message": "Healthy"}

# Configuration Note:
"""
Environment Variables used:
- SECRET_KEY: for JWT signing.
- ALGORITHM: JWT signing algorithm.
- ACCESS_TOKEN_EXPIRE_MINUTES: token expiry time (minutes).
- DB_URL: path (or connection string) for notes db.

Expected .env example (in project root):
SECRET_KEY=supersecret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DB_URL=notes.db

For real-world deployment, use a secure DB backend (e.g. PostgreSQL), robust password hashing, and production-ready secrets.
"""
