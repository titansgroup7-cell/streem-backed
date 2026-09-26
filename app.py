from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from livekit import api
import os
import uuid

# ================== CONFIG ==================
SECRET_KEY = os.getenv("SECRET_KEY", "badilisha-siri-yako-ndefu-sana-123456")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # wiki 1

LIVEKIT_API_KEY = os.getenv("LIVEKIT_API_KEY", "nrxdvx2grzt83xrf9csgejwr")
LIVEKIT_API_SECRET = os.getenv("LIVEKIT_API_SECRET", "m3op2fhzz88dja2wjxyth5auhtomups94wnc26otuwj0as87y36er6zcm2h6cujz")
LIVEKIT_URL = os.getenv("LIVEKIT_URL", "wss://livekit-production-85d3.up.railway.app")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./live.db")

# ================== DATABASE ==================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class LiveRoom(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(String, unique=True, index=True)
    title = Column(String)
    host_id = Column(Integer)
    is_public = Column(Boolean, default=True)
    is_live = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ================== SECURITY ==================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ================== SCHEMAS ==================
class UserCreate(BaseModel):
    username: str
    password: str

class RoomCreate(BaseModel):
    title: str
    is_public: bool = True

class TokenRequest(BaseModel):
    room_id: str
    identity: str
    role: str = "viewer"  # host, guest, viewer

# ================== APP ==================
app = FastAPI(title="Live Stream API")

# ========== CORS (MUHIMU) ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://streemfronted-production.up.railway.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Live Stream API is running"}

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_user = User(
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully", "username": new_user.username}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username
    }

@app.post("/rooms")
def create_room(room: RoomCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    room_id = str(uuid.uuid4())[:8]
    
    new_room = LiveRoom(
        room_id=room_id,
        title=room.title,
        host_id=current_user.id,
        is_public=room.is_public,
        is_live=True
    )
    db.add(new_room)
    db.commit()
    
    return {
        "room_id": room_id,
        "title": room.title,
        "is_public": room.is_public,
        "join_url": f"/live/{room_id}"
    }

@app.get("/rooms/{room_id}")
def get_room(room_id: str, db: Session = Depends(get_db)):
    room = db.query(LiveRoom).filter(LiveRoom.room_id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    return {
        "room_id": room.room_id,
        "title": room.title,
        "is_public": room.is_public,
        "is_live": room.is_live
    }

@app.post("/token")
def get_livekit_token(req: TokenRequest, current_user: User = Depends(get_current_user)):
    can_publish = req.role in ["host", "guest"]
    
    token = api.AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET) \
        .with_identity(req.identity) \
        .with_name(req.identity) \
        .with_grants(api.VideoGrants(
            room_join=True,
            room=req.room_id,
            can_publish=can_publish,
            can_subscribe=True,
            can_publish_data=True,
        ))
    
    return {
        "token": token.to_jwt(),
        "url": LIVEKIT_URL,
        "room_id": req.room_id
    }
